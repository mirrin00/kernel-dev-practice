#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qemu/event_notifier.h"
#include "qemu/timer.h"

#define TYPE_MSI_EXAMPLE "msi-example"

OBJECT_DECLARE_SIMPLE_TYPE(PCIMsiExampleState, MSI_EXAMPLE)

struct PCIMsiExampleState {
    PCIDevice parent_obj;

    QEMUTimer timer;
};

#define MSI_EXAMPLE_VENDOR_ID 0x1337
#define MSI_EXAMPLE_DEVICE_ID 0x0001

static void msi_example_timer(void *opaque)
{
    PCIMsiExampleState *d = opaque;

    msi_notify(&d->parent_obj, 0);

    fprintf(stderr, "msi-example: sent msi irq\n");

    timer_mod(&d->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
}

static void msi_example_realize(PCIDevice *pci_dev, Error **errp)
{
    PCIMsiExampleState *d = MSI_EXAMPLE(pci_dev);
    uint8_t *pci_conf = pci_dev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pci_dev, 0, 1, true, false, errp)) {
        return;
    }

    timer_init_ms(&d->timer, QEMU_CLOCK_VIRTUAL, msi_example_timer, d);
    timer_mod(&d->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 5000);

    fprintf(stderr, "msi-example: loaded\n");
}

static void msi_example_exit(PCIDevice *pdev)
{
    PCIMsiExampleState *d = MSI_EXAMPLE(pdev);

    timer_del(&d->timer);
    msi_uninit(pdev);

    fprintf(stderr, "msi-example: unloaded\n");
}

static void msi_example_class_init(ObjectClass *class, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = msi_example_realize;
    k->exit = msi_example_exit;
    
    k->vendor_id = MSI_EXAMPLE_VENDOR_ID;
    k->device_id = MSI_EXAMPLE_DEVICE_ID;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo msi_example_info[] = {
    {
        .name = TYPE_MSI_EXAMPLE,
        .parent = TYPE_PCI_DEVICE,
        .instance_size = sizeof(PCIMsiExampleState),
        .class_init = msi_example_class_init,
        .interfaces = (InterfaceInfo[]) {
            { INTERFACE_CONVENTIONAL_PCI_DEVICE },
            { },
        },
    }
};

DEFINE_TYPES(msi_example_info)
