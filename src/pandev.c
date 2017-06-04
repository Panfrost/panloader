/*
 * © Copyright 2017 The BiOpenly Community
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

#include <mali-ioctl.h>

static int
pandev_get_driver_version(int fd, unsigned *major, unsigned *minor)
{
	struct mali_ioctl_get_version args = {0};
	int rc;

	/* So far this seems to be the only ioctl that uses 0x80 for dir */
	rc = ioctl(fd, MALI_IOCTL_GET_VERSION, &args);
	if (rc)
		return rc;

	*major = args.major;
	*minor = args.minor;

	return 0;
}

/**
 * Open the device file for communicating with the mali kernelspace driver,
 * and make sure it's a version of the kernel driver we're familiar with.
 *
 * Returns: fd on success, -1 on failure
 */
int
pandev_open()
{
	int fd = open("/dev/mali0", O_RDWR | O_NONBLOCK | O_CLOEXEC),
	    rc;
	unsigned major, minor;

	if (fd < 0)
		return fd;

	rc = pandev_get_driver_version(fd, &major, &minor);
	if (rc)
		return rc;

	printf("Found kernel driver version v%d.%d at /dev/mali0\n",
	       major, minor);

	/* We only support using v10 since this is the kernel driver version
	 * HiKey 960's come with pre-built on Android. Mali changes things a
	 * lot, so it's not worth the effort to support anything else
	 */
	if (major != 10) {
		fprintf(stderr,
			"Warning! This has only been tested with v10 of the "
			"Bifrost kernel driver. There is no guarantee anything "
			"will work with this version.\n");
	}

	return fd;
}
