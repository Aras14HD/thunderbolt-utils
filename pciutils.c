#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "pciutils.h"

void do_pci_rescan()
{
	char *path = "echo 1 > /sys/bus/pci/rescan";

	do_bash_cmd(switch_cmd_to_root(path));
}

void remove_pci_dev(const char *pci_id)
{
	char path[MAX_LEN];

	snprintf(path, sizeof(path), "echo 1 > %s%s/remove", pci_dev_sysfs_path,
		 pci_id);
	do_bash_cmd(switch_cmd_to_root(path));
}

struct vdid* get_vdid(const char *pci_id)
{
	char *vdid_char = malloc(MAX_LEN * sizeof(char));
	struct vdid *vdid = malloc(sizeof(struct vdid));
	char path[MAX_LEN];
	char *bash_result;
	u16 pos;

	snprintf(path, sizeof(path), "lspci -n -s %s", pci_id);

	bash_result = do_bash_cmd(path);

	pos = strpos(bash_result, INTEL_VID, 0);

	strncpy(vdid_char, bash_result + pos, TRIM_VDID_PATH - 1);

	strncpy(vdid->vendor_id, vdid_char, VDID_LEN);
	strncpy(vdid->device_id, vdid_char + VDID_LEN + 1, VDID_LEN);
	vdid->vendor_id[VDID_LEN] = '\0';
	vdid->device_id[VDID_LEN] = '\0';
	return vdid;
}

/* Make the respective PCIe device use DMA */
void allow_bus_master(const char *pci_id)
{
	char path[MAX_LEN];
	char *root_cmd;

	/* To avoid any conflicts, set the MM mapping accessibility also */
	snprintf(path, sizeof(path), "setpci -s %s 0x%x.B=0x%x", pci_id, PCI_CMD,
		 PCI_CMD_MASTER | PCI_CMD_MEM);

	root_cmd = switch_cmd_to_root(path);
	do_bash_cmd(root_cmd);
}

/*u32 read_pci_cfg_long(const struct vfio_hlvl_params *params, u64 off)
{
	struct vfio_region_info *reg_info = find_bar_for_off;
	u64 page_aligned_off;
	void *user_va;
	u32 mem;
	printf("flags:%x\n", reg_info->flags);
	printf("size:%x\n", reg_info->size);
	off += reg_info->offset;
	printf("%llu\n", off);
	page_aligned_off = get_page_aligned_addr(off);
	printf("%llu\n", page_aligned_off);
	user_va = get_user_mapped_read_va(params->device, off);
	printf("add:%d ret:%d\n", user_va, errno);
	mem = *(u32*)(user_va);
	printf("%d\n", mem);
	unmap_user_mapped_va(user_va);

	return mem;
}*/

/*static u32 host_class_id = 0x0c0340;

struct pci_access* init_pci(void)
{
	struct pci_access *pacc;

	pacc = pci_alloc();
	pci_init(pacc);
	pci_scan_bus(pacc);

	return pacc;
}

void clean_pci(struct pci_access *pacc)
{
	pci_cleanup(pacc);
}

bool find_host_controller(void)
{
	struct pci_access *pacc;
	struct pci_dev *pdev;
	bool present = false;
	u32 class_id;

	pacc = init_pci();

	for (pdev = pacc->devices; pdev; pdev = pdev->next) {
		class_id = pci_read_long(pdev, PCI_CLASS_REVISION);
		class_id = class_id >> 8;
		if (class_id == host_class_id) {
			printf("found USB4 host controller: %04x:%02x:%02x.%d\n", pdev->domain,
				pdev->bus, pdev->dev, pdev->func);

			present = true;
		}
	}

	clean_pci(pacc);

	return present;
}*/
