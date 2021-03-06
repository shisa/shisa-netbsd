/*
 * Copyright 1998-2003 VIA Technologies, Inc. All Rights Reserved.
 * Copyright 2001-2003 S3 Graphics, Inc. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * VIA, S3 GRAPHICS, AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifndef _VIA_DRV_H_
#define _VIA_DRV_H_

#define DRIVER_AUTHOR	"Various"

#define DRIVER_NAME		"via"
#define DRIVER_DESC		"VIA Unichrome / Pro"

#include <dev/pci/drm/via_verifier.h>

/*
 * Registers go here.
 */


#define CMDBUF_ALIGNMENT_SIZE   (0x100)
#define CMDBUF_ALIGNMENT_MASK   (0x0ff)

/* defines for VIA 3D registers */
#define VIA_REG_STATUS	        0x400
#define VIA_REG_TRANSET	        0x43C
#define VIA_REG_TRANSPACE       0x440

/* VIA_REG_STATUS(0x400): Engine Status */
#define VIA_CMD_RGTR_BUSY       0x00000080	/* Command Regulator is busy */
#define VIA_2D_ENG_BUSY	        0x00000001	/* 2D Engine is busy */
#define VIA_3D_ENG_BUSY	        0x00000002	/* 3D Engine is busy */
#define VIA_VR_QUEUE_BUSY       0x00020000	/* Virtual Queue is busy */



#if defined(__linux__)
#include "via_dmablit.h"

/*
 * This define and all its references can be removed when
 * the DMA blit code has been implemented for FreeBSD.
 */
#define VIA_HAVE_DMABLIT 1
#define VIA_HAVE_CORE_MM 1
#define VIA_HAVE_FENCE   1
#define VIA_HAVE_BUFFER  1
#endif

#define VIA_PCI_BUF_SIZE 60000
#define VIA_FIRE_BUF_SIZE  1024
#define VIA_NUM_IRQS 4

typedef struct drm_via_ring_buffer {
	drm_local_map_t map;
	char *virtual_start;
} drm_via_ring_buffer_t;

typedef uint32_t maskarray_t[5];

typedef struct drm_via_irq {
	atomic_t irq_received;
	uint32_t pending_mask;
	uint32_t enable_mask;
	wait_queue_head_t irq_queue;
} drm_via_irq_t;
	
typedef struct drm_via_private {
	drm_via_sarea_t *sarea_priv;
	drm_local_map_t *sarea;
	drm_local_map_t *fb;
	drm_local_map_t *mmio;
	unsigned long agpAddr;
	wait_queue_head_t decoder_queue[VIA_NR_XVMC_LOCKS];
	char *dma_ptr;
	unsigned int dma_low;
	unsigned int dma_high;
	unsigned int dma_offset;
	uint32_t dma_wrap;
	volatile uint32_t *last_pause_ptr;
	volatile uint32_t *hw_addr_ptr;
	drm_via_ring_buffer_t ring;
	struct timeval last_vblank;
	int last_vblank_valid;
	unsigned usec_per_vblank;
	drm_via_state_t hc_state;
	char pci_buf[VIA_PCI_BUF_SIZE];
	const uint32_t *fire_offsets[VIA_FIRE_BUF_SIZE];
	uint32_t num_fire_offsets;
	int chipset;
	drm_via_irq_t via_irqs[VIA_NUM_IRQS];
	unsigned num_irqs;
	maskarray_t *irq_masks;
	uint32_t irq_enable_mask; 
	uint32_t irq_pending_mask;	
	int *irq_map;
	/* Memory manager stuff */
#ifdef VIA_HAVE_CORE_MM
	unsigned int idle_fault;
	drm_sman_t sman;
	int vram_initialized;
	int agp_initialized;
	unsigned long vram_offset;
	unsigned long agp_offset;
#endif
#ifdef VIA_HAVE_DMABLIT
	drm_via_blitq_t blit_queues[VIA_NUM_BLIT_ENGINES];
#endif
        uint32_t dma_diff;
#ifdef VIA_HAVE_FENCE
	spinlock_t fence_lock;
	uint32_t emit_0_sequence;
	int have_idlelock;
	struct timer_list fence_timer;
#endif
} drm_via_private_t;

enum via_family {
  VIA_OTHER = 0,     /* Baseline */
  VIA_PRO_GROUP_A,   /* Another video engine and DMA commands */
  VIA_DX9_0          /* Same video as pro_group_a, but 3D is unsupported */
};

/* VIA MMIO register access */
#define VIA_BASE ((dev_priv->mmio))

#define VIA_READ(reg)		DRM_READ32(VIA_BASE, reg)
#define VIA_WRITE(reg,val)	DRM_WRITE32(VIA_BASE, reg, val)
#define VIA_READ8(reg)		DRM_READ8(VIA_BASE, reg)
#define VIA_WRITE8(reg,val)	DRM_WRITE8(VIA_BASE, reg, val)

extern drm_ioctl_desc_t via_ioctls[];
extern int via_max_ioctl;

extern int via_fb_init(DRM_IOCTL_ARGS);
extern int via_mem_alloc(DRM_IOCTL_ARGS);
extern int via_mem_free(DRM_IOCTL_ARGS);
extern int via_agp_init(DRM_IOCTL_ARGS);
extern int via_map_init(DRM_IOCTL_ARGS);
extern int via_decoder_futex(DRM_IOCTL_ARGS);
extern int via_wait_irq(DRM_IOCTL_ARGS);
extern int via_dma_blit_sync( DRM_IOCTL_ARGS );
extern int via_dma_blit( DRM_IOCTL_ARGS );

extern int via_driver_load(drm_device_t *dev, unsigned long chipset);
extern int via_driver_unload(drm_device_t *dev);
extern int via_final_context(drm_device_t * dev, int context);

extern int via_do_cleanup_map(drm_device_t * dev);
extern int via_driver_vblank_wait(drm_device_t * dev, unsigned int *sequence);

extern irqreturn_t via_driver_irq_handler(DRM_IRQ_ARGS);
extern void via_driver_irq_preinstall(drm_device_t * dev);
extern void via_driver_irq_postinstall(drm_device_t * dev);
extern void via_driver_irq_uninstall(drm_device_t * dev);

extern int via_dma_cleanup(drm_device_t * dev);
extern void via_init_command_verifier(void);
extern int via_driver_dma_quiescent(drm_device_t * dev);
extern void via_init_futex(drm_via_private_t *dev_priv);
extern void via_cleanup_futex(drm_via_private_t *dev_priv);
extern void via_release_futex(drm_via_private_t *dev_priv, int context);

#ifdef VIA_HAVE_CORE_MM
extern void via_reclaim_buffers_locked(drm_device_t *dev, struct file *filp);
extern void via_lastclose(drm_device_t *dev);
#else
extern int via_init_context(drm_device_t * dev, int context);
#endif

#ifdef VIA_HAVE_DMABLIT
extern void via_dmablit_handler(drm_device_t *dev, int engine, int from_irq);
extern void via_init_dmablit(drm_device_t *dev);
#endif

#ifdef VIA_HAVE_FENCE
extern void via_fence_timer(unsigned long data);
extern void via_poke_flush(drm_device_t * dev, uint32_t class);
extern int via_fence_emit_sequence(drm_device_t * dev, uint32_t class,
				   uint32_t flags,
				   uint32_t * sequence,
				   uint32_t * native_type);
extern int via_fence_has_irq(struct drm_device * dev, uint32_t class,
			     uint32_t flags);
#endif

#ifdef VIA_HAVE_BUFFER
extern drm_ttm_backend_t *via_create_ttm_backend_entry(drm_device_t *dev);
extern int via_fence_types(drm_buffer_object_t *bo, uint32_t *class, uint32_t *type);
extern int via_invalidate_caches(drm_device_t *dev, uint32_t buffer_flags);
extern int via_init_mem_type(drm_device_t *dev, uint32_t type,
			       drm_mem_type_manager_t *man);
extern uint32_t via_evict_mask(drm_buffer_object_t *bo);
extern int via_move(drm_buffer_object_t *bo, int evict,
	      	int no_wait, drm_bo_mem_reg_t *new_mem);
#endif

#endif
