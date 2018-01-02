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

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/ip.h>
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

long packet_count  = 0;
int packet_major   = PACKET_MAJOR;
int packet_minor   = PACKET_MINOR;
int packet_nr_devs = PACKET_NR_DEVS;

static struct cdev   packet_cdev;
static dev_t         packet_dev_id;
static struct class  *packet_class;
static struct device *packet_dev;

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

static int packet_mem_proc_open(struct inode *inode,
                                struct file *file);

int packet_read_procmem(struct seq_file* s,
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

int packet_read_procmem(struct seq_file* s, void *v)
{
  seq_printf(s,"device: %s\n", PACKET_DEVICE_NAME);
  seq_printf(s,"major: %d\n",packet_major);
  seq_printf(s,"minor: %d\n",packet_minor);
  seq_printf(s,"packet-count: %ld\n",packet_count);
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
int an_packet_init(void);
void an_packet_exit(void);


long an_time(void)
{
  return (jiffies/HZ);
}

int an_packet_init(void)
{
  int ret;
  
  pr_alert("START[%ld]: Loading an/packet module !\n", an_time());
  pr_alert("misc system information:\n");  
  pr_alert("start-time: %ld \n", an_time());
  
  ret = alloc_chrdev_region(&packet_dev_id, PACKET_MINOR,
                            PACKET_NR_DEVS, PACKET_DEVICE_NAME);

  if(ret < 0) {    
    goto packet_destroy_class;
  }
  
  packet_major = MAJOR(packet_dev_id);
  
  pr_alert("allocated device with major number: %d\n",
           packet_major);

  nf_register_hooks(packet_filter_ops, ARRAY_SIZE(packet_filter_ops));

#ifdef PACKET_DEBUG /* only when debugging */
  packet_create_proc();
#endif

  pr_alert("DONE[%ld]: Loading an/packet module !\n",
           an_time());
  
  return 0;
  
 packet_destroy_class:  
  return ret;
  
}

void an_packet_exit(void)
{
  pr_alert("START [%ld]: Unloading  an/packet module!\n", an_time());
  
  // unregister_chrdev_region
  unregister_chrdev_region(packet_dev_id, packet_nr_devs);
  
  nf_unregister_hooks(packet_filter_ops, ARRAY_SIZE(packet_filter_ops));
#ifdef PACKET_DEBUG /* use proc only if debugging */
	packet_remove_proc();
#endif
        
  pr_alert("DONE  [%ld]: Unloading  an/packet module!\n", an_time());
}


loff_t
packet_llseek(struct file *filp, loff_t off,
              int whence){ return 0; }

ssize_t
packet_read(struct file *filp, char __user *buf,
            size_t count, loff_t *f_pos){ return 0; }

ssize_t
packet_write(struct file *filp,
             const char __user *buf,
             size_t count, loff_t *f_pos){ return 0; }

int
packet_open(struct inode *inode,
            struct file *filp){ return 0; }

long
packet_ioctl(struct file *filp,
             unsigned int cmd,
             unsigned long arg){ return 0; }

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
  const struct iphdr *iph = ip_hdr(skb);  
  packet_count++;
  return NF_ACCEPT; // always let packets pass through 
}


module_init(an_packet_init);
module_exit(an_packet_exit);
