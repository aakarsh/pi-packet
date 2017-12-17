#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/jiffies.h>
#include <linux/page-flags.h>


int an_pckt_init(void)
{
  pr_alert("howdy packets :)\n");

  pr_alert("Misc System Information:\n");
  pr_alert("start-time: %ld \n", (jiffies/HZ));

  return 0;
}

void an_pckt_exit(void)
{
  pr_alert("Goodbye packets!\n" );
}

module_init(an_pckt_init);
module_exit(an_pckt_exit);
