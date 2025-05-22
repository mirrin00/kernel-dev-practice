#include <linux/module.h>
#include <linux/pci.h>

#define LOG_PRFX "[msi-example]: "
#define MOD_DEBUG(fmt, ...) pr_debug(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(LOG_PRFX fmt "\n", ##__VA_ARGS__)

#define MSI_EXAMPLE_VENDOR_ID 0x1337
#define MSI_EXAMPLE_DEVICE_ID 0x0001

struct pci_device_id devid = {
	PCI_DEVICE(MSI_EXAMPLE_VENDOR_ID, MSI_EXAMPLE_DEVICE_ID)
};

static irqreturn_t msi_handler(int irq, void *dev_id) {
	MOD_INFO("msi_handler\n");
	return IRQ_HANDLED;
}

static int msi_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	int err;
	err = pci_enable_device(dev);
	if (err) {
		MOD_ERR("pci_enable_device error");
		return err;
	}

	err = dma_set_mask(&dev->dev, DMA_BIT_MASK(32));
	if (err) {
		MOD_ERR("dma_set_mask error");
		return err;
	}

	pci_set_master(dev);

	err = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI);
	if (err < 0) {
		MOD_ERR("pci_alloc_irq_vectors error");
		return err;
	}

	err = pci_request_irq(dev, 0, msi_handler, NULL, &devid,
			      "msi-example-irq-handler");
	if (err) {
		pci_free_irq_vectors(dev);
		MOD_ERR("pci_request_irq error");
		return err;
	}
	MOD_INFO("probe\n");

	return 0;
}

static void msi_remove(struct pci_dev *dev) {
	pci_free_irq(dev, 0, &devid);
	pci_free_irq_vectors(dev);
	MOD_INFO("remove\n");
}

struct pci_driver drv = {
	.name = "msi-example",
	.id_table = &devid,
	.probe = msi_probe,
	.remove = msi_remove,
};

static int __init msi_example_init(void)
{
	int err = pci_register_driver(&drv);
	if (err) {
		MOD_ERR("Error occured during pci driver registration!");
		return err;
	}

	MOD_INFO("loaded\n");
	return 0;
}

static void __exit msi_example_exit(void)
{
	pci_unregister_driver(&drv);
	MOD_INFO("unloaded\n");
}

module_init(msi_example_init);
module_exit(msi_example_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrei Gavrilov");
MODULE_DESCRIPTION("Simple MSI Irq handler");