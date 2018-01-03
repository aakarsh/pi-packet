#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/textsearch.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/sctp.h>
#include <net/af_unix.h>

#include <linux/filter.h>
#include <linux/netfilter/x_tables.h>

/**
 * Simple character device which allows one to inspect
 * certain packets.
 */
#define PACKET_MODULE_NAME "packet-listener"
#define PACKET_DEVICE_NAME "packet-listener-device"
#define PACKET_MAJOR        0                 /* dynamic by default */
#define PACKET_MINOR        0                 /* dynamic by default */
#define PACKET_NR_DEVS      1                 /* dynamic by default */

#define DEVICE_NAME "packet-listener"
#define DRIVER_NAME "packet-listener"

#define PACKET_DEBUG 1

struct packet_ip_data {
  __u8	        tos;
  __be16	tot_len;
  __be16	id;
  __be16	frag_off;
  __u8	        ttl;
  __u8	        protocol;
  __sum16	check;
  __be32	saddr;
  __be32	daddr;
};

struct packet_tcp_data {
  __be16	source;
  __be16	dest;
  __be32	seq;
  __be32	ack_seq;
};

struct packet_data {
  struct packet_ip_data  ip;
  struct packet_tcp_data tcp;
};

struct packet_ring {
  long size; // fixed on creation, keep copy on all for convenience
  long index;

  struct packet_data  data;

  struct packet_ring* next;
  struct packet_ring* prev;
};

long packet_tcp_count  = 0;
long packet_udp_count  = 0;
long packet_unknown_count  = 0;

int packet_major   = PACKET_MAJOR;
int packet_minor   = PACKET_MINOR;
int packet_nr_devs = PACKET_NR_DEVS;

static struct cdev    packet_cdev;
static dev_t          packet_dev_id;
static struct class  *packet_class;
static struct device *packet_dev;

// insertions always take place here.
static struct packet_ring* packet_ring_head = NULL;
static DEFINE_SPINLOCK(packet_ring_lock);

struct packet_ring*
packet_ring_create(int size)
{

  struct packet_ring* prev  = NULL;
  struct packet_ring* cur   = NULL;
  struct packet_ring* start = NULL;

  int s = size;
  int i = 0;

  while( s-- > 0 ) {

    // save current
    prev = cur;
    cur  = kmalloc(sizeof(struct packet_ring), GFP_KERNEL);

    if(!cur)
      goto packet_ring_alloc_error;

    cur->size = size;
    cur->index = i++;

    printk(KERN_ERR "Created packet ring index: %ld \n",
           cur->index);

    if(start == NULL)
      start = cur;

    if(prev != NULL) {
      prev->next = cur;
      cur->prev  = prev;
    }
  }

  if(cur != NULL) { // Close the tail
    cur->next = start;
    start->prev = cur;
  }

  s = 2*size; // go around twice
  cur = start;
  while(s-- > 0) {
    printk(KERN_ERR "Verifying packet at index: %ld\n", cur->size);
    cur = cur->next;
  }

  // this is a circuilar linked-list please don't traverse it infinitely
  return start;

  packet_ring_alloc_error:
    printk(KERN_ERR "packet_ring_alloc_error!!");

  return NULL;
}


void
packet_ring_seq_print(struct seq_file* s)
{
  struct packet_ring* cur;
  spin_lock(&packet_ring_lock);

  cur = packet_ring_head;
  int size = cur->size;
  
  while(size-- > 0) {
    seq_printf(s, "-[%3d]----------------------------\n",cur->index);
    // ip headers
    seq_printf(s , "ip-tos : %d\n", cur->data.ip.tos);
    seq_printf(s , "ip-tot_len : %d\n", cur->data.ip.tot_len);
    seq_printf(s , "ip-id : %d\n", cur->data.ip.id);
    seq_printf(s , "ip-frag_off : %d\n", cur->data.ip.frag_off);
    seq_printf(s , "ip-ttl : %d\n", cur->data.ip.ttl);
    seq_printf(s , "ip-protocol : %d\n", cur->data.ip.protocol);
    seq_printf(s , "ip-check : %d\n", cur->data.ip.check);
    seq_printf(s , "ip-saddr : %d\n", cur->data.ip.saddr);
    seq_printf(s , "ip-daddr : %d\n", cur->data.ip.daddr);

    // tcp headers
    seq_printf(s , "tcp-src : %d\n", cur->data.tcp.source);
    seq_printf(s , "tcp-dest: %d\n", cur->data.tcp.dest);
    seq_printf(s , "tcp-seq : %d\n", cur->data.tcp.seq);
    seq_printf(s , "tcp-seq : %d\n", cur->data.tcp.ack_seq);
    seq_printf(s , "------------------------------\n");

    cur = cur->next;
  }

  spin_unlock(&packet_ring_lock);
}


static void
packet_ring_free(void)
{
  struct packet_ring* cur;
  struct packet_ring* next;

  spin_lock(&packet_ring_lock);
  int size =
    (packet_ring_head == NULL) ? 0 : packet_ring_head->size;

  cur = packet_ring_head;
  next = NULL;

  while(size-- > 0) {
    if(cur == NULL)
      break;

    next = cur->next;
    kfree(cur);
    cur = next;
  }

  packet_ring_head = NULL;

  spin_unlock(&packet_ring_lock);
}


void
packet_ring_set(struct packet_ring* pr)
{
  spin_lock(&packet_ring_lock);
  packet_ring_head = pr;
  spin_unlock(&packet_ring_lock);
}


static void
packet_ring_insert_tcp(const struct iphdr*  ip,
                       const struct tcphdr* th)
{
  spin_lock(&packet_ring_lock);
  struct packet_ring* pr = packet_ring_head;
  if(pr == NULL)
    goto done;

  struct packet_data* d = &(pr->data);
  
  // ip: { headers copy } 
  d->ip.tos = ip->tos;
  d->ip.tot_len = ip->tot_len;
  d->ip.id = ip->id;
  d->ip.frag_off = ip->frag_off;
  d->ip.ttl = ip->ttl;
  d->ip.protocol = ip->protocol;
  d->ip.check = ip->check;
  d->ip.saddr = ip->saddr;
  d->ip.daddr = ip->daddr;
  
  // tcp : { src, dest, seq }
  d->tcp.source  = th->source;
  d->tcp.dest    = th->dest;
  d->tcp.seq     = th->seq;
  d->tcp.ack_seq = th->ack_seq;

  pr = pr->next;

 done:
  spin_unlock(&packet_ring_lock);
}




struct packet_listener_device {
  struct device       *dev;
  struct cdev         cdev;
  struct class *packet_class;
  struct module       *owner;
};

static unsigned int
packet_filter_in(const struct nf_hook_ops *ops,
                 struct sk_buff *skb,
                 const struct net_device *in,
                 const struct net_device *out,
                 int (*okfn)(struct sk_buff *));

static struct nf_hook_ops packet_filter_ops[] __read_mostly =
  {
    {
      .hook	= packet_filter_in,
      .pf       = NFPROTO_IPV4,
      .hooknum	= NF_INET_LOCAL_IN,
      .priority	= NF_IP_PRI_NAT_SRC - 2,
    },
  };

static int
packet_mem_proc_open(struct inode *inode,
                     struct file *file);

int
packet_read_procmem(struct seq_file* s,
                    void *v);

static struct file_operations packet_mem_proc_ops = {
	.owner   = THIS_MODULE,
	.open    = packet_mem_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release
};

static int packet_mem_proc_open(struct inode *inode,
                                struct file *file)
{
  return single_open(file, packet_read_procmem, NULL);
}



int
packet_read_procmem(struct seq_file* s,
                    void *v)
{
  seq_printf(s,"device: %s\n", PACKET_DEVICE_NAME);
  seq_printf(s,"major: %d\n", packet_major);
  seq_printf(s,"minor: %d\n", packet_minor);
  seq_printf(s,"packet-tcp-count: %ld\n", packet_tcp_count);
  seq_printf(s,"packet-udp-count: %ld\n", packet_udp_count);
  seq_printf(s,"packet-default-count: %ld\n", packet_unknown_count);

  

  packet_ring_seq_print(s);

  return 0;
}

static void packet_create_proc(void)
{
  proc_create_data("packet_mem", S_IRUGO,
                   NULL, &packet_mem_proc_ops, NULL);
}



static void packet_remove_proc(void)
{
  /* no problem if it was not registered */
  remove_proc_entry("packet_mem", NULL /* parent dir */);
}

loff_t
packet_llseek(struct file *filp, loff_t off,
              int whence);

ssize_t
packet_read(struct file *filp, char __user *buf,
            size_t count, loff_t *f_pos);

ssize_t
packet_write(struct file *filp,
             const char __user *buf,
             size_t count, loff_t *f_pos);

int
packet_open(struct inode *inode,
            struct file *filp);

long
packet_ioctl(struct file *filp,
             unsigned int cmd,
             unsigned long arg);

int
packet_release(struct inode *inode,
               struct file *filp);

struct file_operations packet_fops = {
	.owner =    THIS_MODULE,
	.llseek =   packet_llseek,
	.read =     packet_read,
	.write =    packet_write,
	.unlocked_ioctl = packet_ioctl,
	.open =     packet_open,
	.release =  packet_release,
};

static inline long an_time(void);
int packet_init(void);
void packet_exit(void);


long an_time(void)
{
  return (jiffies/HZ);
}

int packet_init(void)
{
  int ret;

  pr_alert("START[%ld]: Loading an/packet module !\n", an_time());
  pr_alert("misc system information:\n");
  pr_alert("start-time: %ld \n", an_time());

  // Dynamically allococate device major number
  ret = alloc_chrdev_region(&packet_dev_id,
                            PACKET_MINOR,
                            PACKET_NR_DEVS,
                            PACKET_DEVICE_NAME);

  if(ret < 0) {
    goto packet_destroy_class;
  }

  packet_major = MAJOR(packet_dev_id);
  pr_alert("Allocated device with major number: %d\n",
           packet_major);


  // Create charactr device
  cdev_init(&packet_cdev, &packet_fops);
  packet_cdev.owner = THIS_MODULE;
  ret = cdev_add(&packet_cdev,
                 packet_dev_id,
                 PACKET_NR_DEVS);


  if(ret < 0) {
    pr_alert("unable to register device\n");
    goto packet_failed_cdev_add;
  }


  // Create sysfs entries
  packet_class = class_create(THIS_MODULE, PACKET_DEVICE_NAME);
  if(IS_ERR(packet_class))
    goto packet_failed_class_create;

  packet_dev = device_create(packet_class , NULL,
                             packet_dev_id, NULL,
                             PACKET_DEVICE_NAME);

  if(IS_ERR(packet_dev))
    goto packet_failed_dev_create;

  nf_register_hooks(packet_filter_ops, ARRAY_SIZE(packet_filter_ops));

  packet_ring_set(packet_ring_create(5000));


#ifdef PACKET_DEBUG /* only when debugging */
  packet_create_proc();
#endif

  pr_alert("DONE[%ld]: Loading an/packet module !\n",
           an_time());

  return 0;

 packet_failed_dev_create:
  class_destroy(packet_class);
 packet_failed_class_create:
  cdev_del(&packet_cdev);
 packet_failed_cdev_add:
  unregister_chrdev_region(packet_dev_id, PACKET_NR_DEVS);
 packet_destroy_class:
  return ret;

}

void packet_exit(void)
{
  pr_alert("START [%ld]: Unloading  an/packet module!\n", an_time());

  //destory sysfs
  device_destroy(packet_class, packet_dev_id);
  class_destroy(packet_class);

  // remove char device
  cdev_del(&packet_cdev);

  // unregister_chrdev_region
  unregister_chrdev_region(packet_dev_id, packet_nr_devs);

  nf_unregister_hooks(packet_filter_ops, ARRAY_SIZE(packet_filter_ops));


#ifdef PACKET_DEBUG /* use proc only if debugging */
	packet_remove_proc();
#endif

  // Free the packet ring
  packet_ring_free();

  pr_alert("DONE  [%ld]: Unloading  an/packet module!\n", an_time());
}


loff_t
packet_llseek(struct file *filp, loff_t off,
              int whence)
{

  pr_alert("packet_llseek");
  return 0;
}

ssize_t
packet_read(struct file *filp, char __user *buf,
            size_t count, loff_t *f_pos)
{
  pr_alert("packet_read");
  return 0;
}

ssize_t
packet_write(struct file *filp,
             const char __user *buf,
             size_t count, loff_t *f_pos)
{
  pr_alert("packet_write");
  return 0;
}

int
packet_open(struct inode *inode,
            struct file *filp)
{
  pr_alert("packet_open");
  return 0;
}

long
packet_ioctl(struct file *filp,
             unsigned int cmd,
             unsigned long arg)
{
  pr_alert("packet_ioctl");
  return 0;
}

int
packet_release(struct inode *inode,
               struct file *filp){ return 0; }


static unsigned int
packet_filter_in(const struct nf_hook_ops *ops,
                 struct sk_buff *skb,
                 const struct net_device *in,
                 const struct net_device *out,
                 int (*okfn)(struct sk_buff *))
{
  struct udphdr *uh;
  struct tcphdr *th;

  const struct iphdr *iph = ip_hdr(skb);
  switch(iph->protocol) {

  case IPPROTO_TCP: {
    th = tcp_hdr(skb);

    if (th == NULL)
      break;

    packet_ring_insert_tcp(iph,th);

    packet_tcp_count++;
    break;
  }

  case IPPROTO_UDP: {
    packet_udp_count++;
    uh = udp_hdr(skb);
    if (uh == NULL)
      break;

    break;
  }

  default:
    packet_unknown_count++;
  }
  return NF_ACCEPT; // always let packets pass through
}

module_init(packet_init);
module_exit(packet_exit);
MODULE_LICENSE("GPL");
