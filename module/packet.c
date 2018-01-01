#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/io.h>
#include <linux/cdev.h>
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

  
  ret = alloc_chrdev_region(&packet_dev_id,
                            PACKET_MINOR, PACKET_NR_DEVS, PACKET_DEVICE_NAME);

  if(ret < 0) {    
    goto packet_destroy_class;
  }
  
  packet_major = MAJOR(packet_dev_id);

  pr_alert("allocated device with major number: %d\n",
           packet_major);
  
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
  
  pr_alert("DONE  [%ld]: Unloading  an/packet module!\n", an_time());
}


module_init(an_packet_init);
module_exit(an_packet_exit);
