/*	$NetBSD: schedctl.c,v 1.2 2008/01/26 17:52:08 rmind Exp $	*/

/*
 * Copyright (c) 2008, Mindaugas Rasiukevicius <rmind at NetBSD org>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * schedctl(8) - a program to control scheduling of processes and threads.
 */

#include <sys/cdefs.h>

#ifndef lint
__RCSID("$NetBSD: schedctl.c,v 1.2 2008/01/26 17:52:08 rmind Exp $");
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <unistd.h>

#include <sys/pset.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/types.h>

static const char *class_str[] = {
	"SCHED_OTHER",
	"SCHED_FIFO",
	"SCHED_RR"
};

static void	sched_set(pid_t, lwpid_t, struct sched_param *, cpuset_t *);
static void	thread_info(pid_t, lwpid_t);
static cpuset_t	*makecpuset(char *);
static char	*showcpuset(cpuset_t *);
static void	usage(void);

static u_int	ncpu;

int
main(int argc, char **argv)
{
	kvm_t *kd;
	struct kinfo_lwp *lwp_list, *lwp;
	struct sched_param *sp;
	cpuset_t *cpuset;
	int i, count, ch;
	pid_t pid;
	lwpid_t lid;
	bool set;

	ncpu = sysconf(_SC_NPROCESSORS_CONF);

	pid = lid = 0;
	cpuset = NULL;
	set = false;

	sp = malloc(sizeof(struct sched_param));
	if (sp == NULL)
		err(EXIT_FAILURE, "malloc");

	memset(sp, 0, sizeof(struct sched_param));
	sp->sched_class = SCHED_NONE;
	sp->sched_priority = PRI_NONE;

	while ((ch = getopt(argc, argv, "A:C:P:p:t:")) != -1) {
		switch (ch) {
		case 'p':
			/* PID */
			pid = atoi(optarg);
			break;
		case 't':
			/* Thread (LWP) ID */
			lid = atoi(optarg);
			break;
		case 'A':
			/* Affinity */
			cpuset = makecpuset(optarg);
			if (cpuset == NULL) {
				fprintf(stderr, "%s: invalid CPU value\n",
				    getprogname());
				exit(EXIT_FAILURE);
			}
			break;
		case 'C':
			/* Scheduling class */
			sp->sched_class = atoi(optarg);
			if (sp->sched_class < SCHED_OTHER ||
			    sp->sched_class > SCHED_RR) {
				fprintf(stderr,
				    "%s: invalid scheduling class\n",
				    getprogname());
				exit(EXIT_FAILURE);
			}
			set = true;
			break;
		case 'P':
			/* Priority */
			sp->sched_priority = atoi(optarg);
			if (sp->sched_priority < sysconf(_SC_SCHED_PRI_MIN) ||
			    sp->sched_priority > sysconf(_SC_SCHED_PRI_MAX)) {
				fprintf(stderr, "%s: invalid priority\n",
				    getprogname());
				exit(EXIT_FAILURE);
			}
			set = true;
			break;
		default:
			usage();
		}
	}

	/* At least PID must be specified */
	if (pid == 0)
		usage();

	/* Set the scheduling information for thread/process */
	sched_set(pid, lid, set ? sp : NULL, cpuset);

	/* Show information about each thread */
	kd = kvm_open(NULL, NULL, NULL, KVM_NO_FILES, "kvm_open");
	if (kd == NULL)
		err(EXIT_FAILURE, "kvm_open");
	lwp_list = kvm_getlwps(kd, pid, 0, sizeof(struct kinfo_lwp), &count);
	if (lwp_list == NULL)
		err(EXIT_FAILURE, "kvm_getlwps");
	for (lwp = lwp_list, i = 0; i < count; lwp++, i++) {
		if (lid && lid != lwp->l_lid)
			continue;
		thread_info(pid, lwp->l_lid);
	}
	kvm_close(kd);

	free(sp);
	free(cpuset);
	return 0;
}

static void
sched_set(pid_t pid, lwpid_t lid, struct sched_param *sp, cpuset_t *cpuset)
{
	int error;

	if (sp) {
		/* Set the scheduling parameters for the thread */
		error = _sched_setparam(pid, lid, sp);
		if (error < 0)
			err(EXIT_FAILURE, "_sched_setparam");
	}
	if (cpuset) {
		/* Set the CPU-set for affinity */
		error = _sched_setaffinity(pid, lid,
		    sizeof(cpuset_t), cpuset);
		if (error < 0)
			err(EXIT_FAILURE, "_sched_setaffinity");
	}
}

static void
thread_info(pid_t pid, lwpid_t lid)
{
	struct sched_param sp;
	cpuset_t *cpuset;
	char *cpus;
	int error;

	cpuset = malloc(sizeof(cpuset_t));
	if (cpuset == NULL)
		err(EXIT_FAILURE, "malloc");

	error = _sched_getparam(pid, lid, &sp);
	if (error < 0)
		err(EXIT_FAILURE, "_sched_getparam");

	error = _sched_getaffinity(pid, lid, sizeof(cpuset_t), cpuset);
	if (error < 0)
		err(EXIT_FAILURE, "_sched_getaffinity");

	printf("  LID:              %d\n", lid);
	printf("  Priority:         %d\n", sp.sched_priority);
	printf("  Class:            %s\n", class_str[sp.sched_class]);

	cpus = showcpuset(cpuset);
	printf("  Affinity (CPUs):  %s\n", cpus);
	free(cpus);

	free(cpuset);
}

static cpuset_t *
makecpuset(char *str)
{
	cpuset_t *cpuset;
	char *cpustr, *s;

	if (str == NULL)
		return NULL;

	cpuset = malloc(sizeof(cpuset_t));
	if (cpuset == NULL)
		err(EXIT_FAILURE, "malloc");
	memset(cpuset, 0, sizeof(cpuset_t));

	cpustr = strdup(str);
	if (cpustr == NULL)
		err(EXIT_FAILURE, "strdup");
	s = cpustr;

	while (s != NULL) {
		char *p;
		int i;

		/* Get the CPU number and validate the range */
		p = strsep(&s, ",");
		if (p == NULL) {
			free(cpuset);
			cpuset = NULL;
			break;
		}
		i = atoi(p);
		if (i == -1) {
			memset(cpuset, 0, sizeof(cpuset_t));
			break;
		}
		if ((unsigned int)i >= ncpu) {
			free(cpuset);
			cpuset = NULL;
			break;
		}

		/* Set the bit */
		CPU_SET(i, cpuset);
	}

	free(cpustr);
	return cpuset;
}

static char *
showcpuset(cpuset_t *cpuset)
{
	char *buf;
	size_t size;
	int i;

	size = 3 * ncpu;	/* XXX */
	buf = malloc(size + 1);
	if (cpuset == NULL)
		err(EXIT_FAILURE, "malloc");
	memset(buf, '\0', size + 1);

	for (i = 0; i < ncpu; i++)
		if (CPU_ISSET(i, cpuset))
			snprintf(buf, size, "%s%d,", buf, i);

	i = strlen(buf);
	if (i != 0) {
		buf[i - 1] = '\0';
	} else {
		strncpy(buf, "<none>", size);
	}

	return buf;
}

static void
usage(void)
{
	const char *progname = getprogname();

	fprintf(stderr, "usage: %s -p pid [ -t lid ] [ -A processor ]\n"
	    "\t [ -C class ] [ -P priority ]\n", progname);
	exit(EXIT_FAILURE);
}
