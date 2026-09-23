"""GEF syscall tables (Layer 0 core).

Extracted verbatim from gef.py: the module-level syscall data blobs
(syscall_defs, syscall_defs_compat, the 25 *_syscall_tbl tables, plus the
arm_OPTEE/arm_ldelf/x86_16_dos lists) and the Syscall base class together
with its 29 architecture subclasses.

Architecture classes (gef.arch.*) and process predicates (gef.core.process)
are imported lazily inside the methods that use them, so this module stays
importable outside gdb.
"""
import collections
import re

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.color import err



# System call table (linux-7.0-rc7; How to make: see dev/update-syscalls/update-syscalls.py)
# include/linux/syscalls.h
syscall_defs = """
asmlinkage long sys_io_setup(unsigned nr_reqs, aio_context_t __user* ctx);
asmlinkage long sys_io_destroy(aio_context_t ctx);
!asmlinkage long sys_io_submit(aio_context_t ctx_id, long nr, struct iocb __user * __user* iocbpp);
asmlinkage long sys_io_cancel(aio_context_t ctx_id, struct iocb __user* iocb, struct io_event __user* result);
asmlinkage long sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user* events, struct __kernel_timespec __user* timeout);
asmlinkage long sys_io_getevents_time32(__u32 ctx_id, __s32 min_nr, __s32 nr, struct io_event __user* events, struct old_timespec32 __user* timeout);
asmlinkage long sys_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user* events, struct __kernel_timespec __user* timeout, const struct __aio_sigset __user* sig);
asmlinkage long sys_io_pgetevents_time32(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user* events, struct old_timespec32 __user* timeout, const struct __aio_sigset __user* sig);
asmlinkage long sys_io_uring_setup(u32 entries, struct io_uring_params __user* p);
asmlinkage long sys_io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user* argp, size_t argsz);
asmlinkage long sys_io_uring_register(unsigned int fd, unsigned int op, void __user* arg, unsigned int nr_args);
asmlinkage long sys_setxattr(const char __user* path, const char __user* name, const void __user* value, size_t size, int flags);
asmlinkage long sys_setxattrat(int dfd, const char __user* path, unsigned int at_flags, const char __user* name, const struct xattr_args __user* args, size_t size);
asmlinkage long sys_lsetxattr(const char __user* path, const char __user* name, const void __user* value, size_t size, int flags);
asmlinkage long sys_fsetxattr(int fd, const char __user* name, const void __user* value, size_t size, int flags);
asmlinkage long sys_getxattr(const char __user* path, const char __user* name, void __user* value, size_t size);
asmlinkage long sys_getxattrat(int dfd, const char __user* path, unsigned int at_flags, const char __user* name, struct xattr_args __user* args, size_t size);
asmlinkage long sys_lgetxattr(const char __user* path, const char __user* name, void __user* value, size_t size);
asmlinkage long sys_fgetxattr(int fd, const char __user* name, void __user* value, size_t size);
asmlinkage long sys_listxattr(const char __user* path, char __user* list, size_t size);
asmlinkage long sys_listxattrat(int dfd, const char __user* path, unsigned int at_flags, char __user* list, size_t size);
asmlinkage long sys_llistxattr(const char __user* path, char __user* list, size_t size);
asmlinkage long sys_flistxattr(int fd, char __user* list, size_t size);
asmlinkage long sys_removexattr(const char __user* path, const char __user* name);
asmlinkage long sys_removexattrat(int dfd, const char __user* path, unsigned int at_flags, const char __user* name);
asmlinkage long sys_lremovexattr(const char __user* path, const char __user* name);
asmlinkage long sys_fremovexattr(int fd, const char __user* name);
asmlinkage long sys_file_getattr(int dfd, const char __user* filename, struct file_attr __user* attr, size_t usize, unsigned int at_flags);
asmlinkage long sys_file_setattr(int dfd, const char __user* filename, struct file_attr __user* attr, size_t usize, unsigned int at_flags);
asmlinkage long sys_getcwd(char __user* buf, unsigned long size);
asmlinkage long sys_eventfd2(unsigned int count, int flags);
asmlinkage long sys_epoll_create1(int flags);
asmlinkage long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user* event);
asmlinkage long sys_epoll_pwait(int epfd, struct epoll_event __user* events, int maxevents, int timeout, const sigset_t __user* sigmask, size_t sigsetsize);
asmlinkage long sys_epoll_pwait2(int epfd, struct epoll_event __user* events, int maxevents, const struct __kernel_timespec __user* timeout, const sigset_t __user* sigmask, size_t sigsetsize);
asmlinkage long sys_dup(unsigned int fildes);
asmlinkage long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
asmlinkage long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_inotify_init1(int flags);
asmlinkage long sys_inotify_add_watch(int fd, const char __user* path, u32 mask);
asmlinkage long sys_inotify_rm_watch(int fd, __s32 wd);
asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_ioprio_set(int which, int who, int ioprio);
asmlinkage long sys_ioprio_get(int which, int who);
asmlinkage long sys_flock(unsigned int fd, unsigned int cmd);
asmlinkage long sys_mknodat(int dfd, const char __user* filename, umode_t mode, unsigned dev);
asmlinkage long sys_mkdirat(int dfd, const char __user* pathname, umode_t mode);
asmlinkage long sys_unlinkat(int dfd, const char __user* pathname, int flag);
asmlinkage long sys_symlinkat(const char __user* oldname, int newdfd, const char __user* newname);
asmlinkage long sys_linkat(int olddfd, const char __user* oldname, int newdfd, const char __user* newname, int flags);
asmlinkage long sys_renameat(int olddfd, const char __user* oldname, int newdfd, const char __user* newname);
asmlinkage long sys_umount(char __user* name, int flags);
asmlinkage long sys_mount(char __user* dev_name, char __user* dir_name, char __user* type, unsigned long flags, void __user* data);
asmlinkage long sys_pivot_root(const char __user* new_root, const char __user* put_old);
asmlinkage long sys_statfs(const char __user* path, struct statfs __user* buf);
asmlinkage long sys_statfs64(const char __user* path, size_t sz, struct statfs64 __user* buf);
asmlinkage long sys_fstatfs(unsigned int fd, struct statfs __user* buf);
asmlinkage long sys_fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user* buf);
asmlinkage long sys_statmount(const struct mnt_id_req __user* req, struct statmount __user* buf, size_t bufsize, unsigned int flags);
asmlinkage long sys_listmount(const struct mnt_id_req __user* req, u64 __user* mnt_ids, size_t nr_mnt_ids, unsigned int flags);
asmlinkage long sys_listns(const struct ns_id_req __user* req, u64 __user* ns_ids, size_t nr_ns_ids, unsigned int flags);
asmlinkage long sys_truncate(const char __user* path, long length);
asmlinkage long sys_ftruncate(unsigned int fd, off_t length);
asmlinkage long sys_truncate64(const char __user* path, loff_t length);
asmlinkage long sys_ftruncate64(unsigned int fd, loff_t length);
asmlinkage long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);
asmlinkage long sys_faccessat(int dfd, const char __user* filename, int mode);
asmlinkage long sys_faccessat2(int dfd, const char __user* filename, int mode, int flags);
asmlinkage long sys_chdir(const char __user* filename);
asmlinkage long sys_fchdir(unsigned int fd);
asmlinkage long sys_chroot(const char __user* filename);
asmlinkage long sys_fchmod(unsigned int fd, umode_t mode);
asmlinkage long sys_fchmodat(int dfd, const char __user* filename, umode_t mode);
asmlinkage long sys_fchmodat2(int dfd, const char __user* filename, umode_t mode, unsigned int flags);
asmlinkage long sys_fchownat(int dfd, const char __user* filename, uid_t user, gid_t group, int flag);
asmlinkage long sys_fchown(unsigned int fd, uid_t user, gid_t group);
asmlinkage long sys_openat(int dfd, const char __user* filename, int flags, umode_t mode);
asmlinkage long sys_openat2(int dfd, const char __user* filename, struct open_how __user* how, size_t size);
asmlinkage long sys_close(unsigned int fd);
asmlinkage long sys_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
asmlinkage long sys_vhangup(void);
asmlinkage long sys_pipe2(int __user* fildes, int flags);
asmlinkage long sys_quotactl(unsigned int cmd, const char __user* special, qid_t id, void __user* addr);
asmlinkage long sys_quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void __user* addr);
asmlinkage long sys_getdents64(unsigned int fd, struct linux_dirent64 __user* dirent, unsigned int count);
asmlinkage long sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user* result, unsigned int whence);
asmlinkage long sys_lseek(unsigned int fd, off_t offset, unsigned int whence);
asmlinkage long sys_read(unsigned int fd, char __user* buf, size_t count);
asmlinkage long sys_write(unsigned int fd, const char __user* buf, size_t count);
asmlinkage long sys_readv(unsigned long fd, const struct iovec __user* vec, unsigned long vlen);
asmlinkage long sys_writev(unsigned long fd, const struct iovec __user* vec, unsigned long vlen);
asmlinkage long sys_pread64(unsigned int fd, char __user* buf, size_t count, loff_t pos);
asmlinkage long sys_pwrite64(unsigned int fd, const char __user* buf, size_t count, loff_t pos);
asmlinkage long sys_preadv(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long sys_pwritev(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long sys_sendfile64(int out_fd, int in_fd, loff_t __user* offset, size_t count);
!asmlinkage long sys_pselect6(int n, fd_set __user* inp, fd_set __user* outp, fd_set __user* exp, struct __kernel_timespec __user* tsp, void __user* sig);
!asmlinkage long sys_pselect6_time32(int n, fd_set __user* inp, fd_set __user* outp, fd_set __user* exp, struct old_timespec32 __user* tsp, void __user* sig);
!asmlinkage long sys_ppoll(struct pollfd __user* ufds, unsigned int nfds, struct __kernel_timespec __user* tsp, const sigset_t __user* sigmask, size_t sigsetsize);
!asmlinkage long sys_ppoll_time32(struct pollfd __user* ufds, unsigned int nfds, struct old_timespec32 __user* tsp, const sigset_t __user* sigmask, size_t sigsetsize);
asmlinkage long sys_signalfd4(int ufd, sigset_t __user* user_mask, size_t sizemask, int flags);
asmlinkage long sys_vmsplice(int fd, const struct iovec __user* iov, unsigned long nr_segs, unsigned int flags);
asmlinkage long sys_splice(int fd_in, loff_t __user* off_in, int fd_out, loff_t __user* off_out, size_t len, unsigned int flags);
asmlinkage long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);
asmlinkage long sys_readlinkat(int dfd, const char __user* path, char __user* buf, int bufsiz);
asmlinkage long sys_newfstatat(int dfd, const char __user* filename, struct stat __user* statbuf, int flag);
asmlinkage long sys_newfstat(unsigned int fd, struct stat __user* statbuf);
asmlinkage long sys_fstat64(unsigned long fd, struct stat64 __user* statbuf);
asmlinkage long sys_fstatat64(int dfd, const char __user* filename, struct stat64 __user* statbuf, int flag);
asmlinkage long sys_sync(void);
asmlinkage long sys_fsync(unsigned int fd);
asmlinkage long sys_fdatasync(unsigned int fd);
asmlinkage long sys_sync_file_range2(int fd, unsigned int flags, loff_t offset, loff_t nbytes);
asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
asmlinkage long sys_timerfd_create(int clockid, int flags);
asmlinkage long sys_timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user* utmr, struct __kernel_itimerspec __user* otmr);
asmlinkage long sys_timerfd_gettime(int ufd, struct __kernel_itimerspec __user* otmr);
asmlinkage long sys_timerfd_gettime32(int ufd, struct old_itimerspec32 __user* otmr);
asmlinkage long sys_timerfd_settime32(int ufd, int flags, const struct old_itimerspec32 __user* utmr, struct old_itimerspec32 __user* otmr);
asmlinkage long sys_utimensat(int dfd, const char __user* filename, struct __kernel_timespec __user* utimes, int flags);
asmlinkage long sys_utimensat_time32(unsigned int dfd, const char __user* filename, struct old_timespec32 __user* t, int flags);
asmlinkage long sys_acct(const char __user* name);
asmlinkage long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);
asmlinkage long sys_capset(cap_user_header_t header, const cap_user_data_t data);
asmlinkage long sys_personality(unsigned int personality);
asmlinkage long sys_exit(int error_code);
asmlinkage long sys_exit_group(int error_code);
asmlinkage long sys_waitid(int which, pid_t pid, struct siginfo __user* infop, int options, struct rusage __user* ru);
asmlinkage long sys_set_tid_address(int __user* tidptr);
asmlinkage long sys_unshare(unsigned long unshare_flags);
asmlinkage long sys_futex(u32 __user* uaddr, int op, u32 val, const struct __kernel_timespec __user* utime, u32 __user* uaddr2, u32 val3);
asmlinkage long sys_futex_time32(u32 __user* uaddr, int op, u32 val, const struct old_timespec32 __user* utime, u32 __user* uaddr2, u32 val3);
asmlinkage long sys_get_robust_list(int pid, struct robust_list_head __user * __user * head_ptr, size_t __user* len_ptr);
asmlinkage long sys_set_robust_list(struct robust_list_head __user* head, size_t len);
asmlinkage long sys_futex_waitv(struct futex_waitv __user* waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec __user* timeout, clockid_t clockid);
asmlinkage long sys_futex_wake(void __user* uaddr, unsigned long mask, int nr, unsigned int flags);
asmlinkage long sys_futex_wait(void __user* uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec __user* timespec, clockid_t clockid);
asmlinkage long sys_futex_requeue(struct futex_waitv __user* waiters, unsigned int flags, int nr_wake, int nr_requeue);
asmlinkage long sys_nanosleep(struct __kernel_timespec __user* rqtp, struct __kernel_timespec __user* rmtp);
asmlinkage long sys_nanosleep_time32(struct old_timespec32 __user* rqtp, struct old_timespec32 __user* rmtp);
asmlinkage long sys_getitimer(int which, struct __kernel_old_itimerval __user* value);
asmlinkage long sys_setitimer(int which, struct __kernel_old_itimerval __user* value, struct __kernel_old_itimerval __user* ovalue);
asmlinkage long sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user* segments, unsigned long flags);
asmlinkage long sys_init_module(void __user* umod, unsigned long len, const char __user* uargs);
asmlinkage long sys_delete_module(const char __user* name_user, unsigned int flags);
asmlinkage long sys_timer_create(clockid_t which_clock, struct sigevent __user* timer_event_spec, timer_t __user* created_timer_id);
asmlinkage long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user* setting);
asmlinkage long sys_timer_getoverrun(timer_t timer_id);
asmlinkage long sys_timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user* new_setting, struct __kernel_itimerspec __user* old_setting);
asmlinkage long sys_timer_delete(timer_t timer_id);
asmlinkage long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec __user* tp);
asmlinkage long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec __user* tp);
asmlinkage long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec __user* tp);
asmlinkage long sys_clock_nanosleep(clockid_t which_clock, int flags, const struct __kernel_timespec __user* rqtp, struct __kernel_timespec __user* rmtp);
asmlinkage long sys_timer_gettime32(timer_t timer_id, struct old_itimerspec32 __user* setting);
asmlinkage long sys_timer_settime32(timer_t timer_id, int flags, struct old_itimerspec32 __user* new, struct old_itimerspec32 __user* old);
asmlinkage long sys_clock_settime32(clockid_t which_clock, struct old_timespec32 __user* tp);
asmlinkage long sys_clock_gettime32(clockid_t which_clock, struct old_timespec32 __user* tp);
asmlinkage long sys_clock_getres_time32(clockid_t which_clock, struct old_timespec32 __user* tp);
asmlinkage long sys_clock_nanosleep_time32(clockid_t which_clock, int flags, struct old_timespec32 __user* rqtp, struct old_timespec32 __user* rmtp);
asmlinkage long sys_syslog(int type, char __user* buf, int len);
asmlinkage long sys_ptrace(long request, long pid, unsigned long addr, unsigned long data);
asmlinkage long sys_sched_setparam(pid_t pid, struct sched_param __user* param);
asmlinkage long sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user* param);
asmlinkage long sys_sched_getscheduler(pid_t pid);
asmlinkage long sys_sched_getparam(pid_t pid, struct sched_param __user* param);
asmlinkage long sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user* user_mask_ptr);
asmlinkage long sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user* user_mask_ptr);
asmlinkage long sys_sched_yield(void);
asmlinkage long sys_sched_get_priority_max(int policy);
asmlinkage long sys_sched_get_priority_min(int policy);
asmlinkage long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user* interval);
asmlinkage long sys_sched_rr_get_interval_time32(pid_t pid, struct old_timespec32 __user* interval);
asmlinkage long sys_restart_syscall(void);
asmlinkage long sys_kill(pid_t pid, int sig);
asmlinkage long sys_tkill(pid_t pid, int sig);
asmlinkage long sys_tgkill(pid_t tgid, pid_t pid, int sig);
asmlinkage long sys_sigaltstack(const struct sigaltstack __user* uss, struct sigaltstack __user* uoss);
asmlinkage long sys_rt_sigsuspend(sigset_t __user* unewset, size_t sigsetsize);
!asmlinkage long sys_rt_sigaction(int sig, const struct sigaction __user* act, struct sigaction __user* oact, size_t sigsetsize);
asmlinkage long sys_rt_sigprocmask(int how, sigset_t __user* set, sigset_t __user* oset, size_t sigsetsize);
asmlinkage long sys_rt_sigpending(sigset_t __user* set, size_t sigsetsize);
asmlinkage long sys_rt_sigtimedwait(const sigset_t __user* uthese, siginfo_t __user* uinfo, const struct __kernel_timespec __user* uts, size_t sigsetsize);
asmlinkage long sys_rt_sigtimedwait_time32(const sigset_t __user* uthese, siginfo_t __user* uinfo, const struct old_timespec32 __user* uts, size_t sigsetsize);
asmlinkage long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user* uinfo);
asmlinkage long sys_setpriority(int which, int who, int niceval);
asmlinkage long sys_getpriority(int which, int who);
asmlinkage long sys_reboot(int magic1, int magic2, unsigned int cmd, void __user* arg);
asmlinkage long sys_setregid(gid_t rgid, gid_t egid);
asmlinkage long sys_setgid(gid_t gid);
asmlinkage long sys_setreuid(uid_t ruid, uid_t euid);
asmlinkage long sys_setuid(uid_t uid);
asmlinkage long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
asmlinkage long sys_getresuid(uid_t __user* ruid, uid_t __user* euid, uid_t __user* suid);
asmlinkage long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
asmlinkage long sys_getresgid(gid_t __user* rgid, gid_t __user* egid, gid_t __user* sgid);
asmlinkage long sys_setfsuid(uid_t uid);
asmlinkage long sys_setfsgid(gid_t gid);
asmlinkage long sys_times(struct tms __user* tbuf);
asmlinkage long sys_setpgid(pid_t pid, pid_t pgid);
asmlinkage long sys_getpgid(pid_t pid);
asmlinkage long sys_getsid(pid_t pid);
asmlinkage long sys_setsid(void);
asmlinkage long sys_getgroups(int gidsetsize, gid_t __user* grouplist);
asmlinkage long sys_setgroups(int gidsetsize, gid_t __user* grouplist);
asmlinkage long sys_newuname(struct new_utsname __user* name);
asmlinkage long sys_sethostname(char __user* name, int len);
asmlinkage long sys_setdomainname(char __user* name, int len);
asmlinkage long sys_getrlimit(unsigned int resource, struct rlimit __user* rlim);
asmlinkage long sys_setrlimit(unsigned int resource, struct rlimit __user* rlim);
asmlinkage long sys_getrusage(int who, struct rusage __user* ru);
asmlinkage long sys_umask(int mask);
asmlinkage long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
asmlinkage long sys_getcpu(unsigned __user* cpu, unsigned __user* node, void __user* cache);
asmlinkage long sys_gettimeofday(struct __kernel_old_timeval __user* tv, struct timezone __user* tz);
asmlinkage long sys_settimeofday(struct __kernel_old_timeval __user* tv, struct timezone __user* tz);
asmlinkage long sys_adjtimex(struct __kernel_timex __user* txc_p);
asmlinkage long sys_adjtimex_time32(struct old_timex32 __user* txc_p);
asmlinkage long sys_getpid(void);
asmlinkage long sys_getppid(void);
asmlinkage long sys_getuid(void);
asmlinkage long sys_geteuid(void);
asmlinkage long sys_getgid(void);
asmlinkage long sys_getegid(void);
asmlinkage long sys_gettid(void);
asmlinkage long sys_sysinfo(struct sysinfo __user* info);
asmlinkage long sys_mq_open(const char __user* name, int oflag, umode_t mode, struct mq_attr __user* attr);
asmlinkage long sys_mq_unlink(const char __user* name);
asmlinkage long sys_mq_timedsend(mqd_t mqdes, const char __user* msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user* abs_timeout);
asmlinkage long sys_mq_timedreceive(mqd_t mqdes, char __user* msg_ptr, size_t msg_len, unsigned int __user* msg_prio, const struct __kernel_timespec __user* abs_timeout);
asmlinkage long sys_mq_notify(mqd_t mqdes, const struct sigevent __user* notification);
asmlinkage long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user* mqstat, struct mq_attr __user* omqstat);
asmlinkage long sys_mq_timedreceive_time32(mqd_t mqdes, char __user* u_msg_ptr, unsigned int msg_len, unsigned int __user* u_msg_prio, const struct old_timespec32 __user* u_abs_timeout);
asmlinkage long sys_mq_timedsend_time32(mqd_t mqdes, const char __user* u_msg_ptr, unsigned int msg_len, unsigned int msg_prio, const struct old_timespec32 __user* u_abs_timeout);
asmlinkage long sys_msgget(key_t key, int msgflg);
asmlinkage long sys_old_msgctl(int msqid, int cmd, struct msqid_ds __user* buf);
asmlinkage long sys_msgctl(int msqid, int cmd, struct msqid_ds __user* buf);
asmlinkage long sys_msgrcv(int msqid, struct msgbuf __user* msgp, size_t msgsz, long msgtyp, int msgflg);
asmlinkage long sys_msgsnd(int msqid, struct msgbuf __user* msgp, size_t msgsz, int msgflg);
asmlinkage long sys_semget(key_t key, int nsems, int semflg);
asmlinkage long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
asmlinkage long sys_old_semctl(int semid, int semnum, int cmd, unsigned long arg);
asmlinkage long sys_semtimedop(int semid, struct sembuf __user* sops, unsigned nsops, const struct __kernel_timespec __user* timeout);
asmlinkage long sys_semtimedop_time32(int semid, struct sembuf __user* sops, unsigned nsops, const struct old_timespec32 __user* timeout);
asmlinkage long sys_semop(int semid, struct sembuf __user* sops, unsigned nsops);
asmlinkage long sys_shmget(key_t key, size_t size, int flag);
asmlinkage long sys_old_shmctl(int shmid, int cmd, struct shmid_ds __user* buf);
asmlinkage long sys_shmctl(int shmid, int cmd, struct shmid_ds __user* buf);
asmlinkage long sys_shmat(int shmid, char __user* shmaddr, int shmflg);
asmlinkage long sys_shmdt(char __user* shmaddr);
!asmlinkage long sys_socket(int family, int type, int protocol);
!asmlinkage long sys_socketpair(int family, int type, int protocol, int __user* usockvec);
!asmlinkage long sys_bind(int fd, struct sockaddr __user* umyaddr, int addrlen);
!asmlinkage long sys_listen(int fd, int backlog);
!asmlinkage long sys_accept(int fd, struct sockaddr __user* upeer_sockaddr, int __user* upeer_addrlen);
!asmlinkage long sys_connect(int fd, struct sockaddr __user* uservaddr, int addrlen);
!asmlinkage long sys_getsockname(int fd, struct sockaddr __user* usockaddr, int __user* usockaddr_len);
!asmlinkage long sys_getpeername(int fd, struct sockaddr __user* usockaddr, int __user* usockaddr_len);
!asmlinkage long sys_sendto(int fd, void __user* buff, size_t len, unsigned int flags, struct sockaddr __user* addr, int addr_len);
!asmlinkage long sys_recvfrom(int fd, void __user* ubuf, size_t size, unsigned int flags, struct sockaddr __user* addr, int __user* addr_len);
asmlinkage long sys_setsockopt(int fd, int level, int optname, char __user* optval, int optlen);
asmlinkage long sys_getsockopt(int fd, int level, int optname, char __user* optval, int __user* optlen);
!asmlinkage long sys_shutdown(int fd, int how);
asmlinkage long sys_sendmsg(int fd, struct user_msghdr __user* msg, unsigned flags);
asmlinkage long sys_recvmsg(int fd, struct user_msghdr __user* msg, unsigned flags);
asmlinkage long sys_readahead(int fd, loff_t offset, size_t count);
asmlinkage long sys_brk(unsigned long brk);
asmlinkage long sys_munmap(unsigned long addr, size_t len);
asmlinkage long sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
asmlinkage long sys_add_key(const char __user* _type, const char __user* _description, const void __user* _payload, size_t plen, key_serial_t destringid);
asmlinkage long sys_request_key(const char __user* _type, const char __user* _description, const char __user* _callout_info, key_serial_t destringid);
asmlinkage long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
#asmlinkage long sys_clone(unsigned long, unsigned long, int __user*, unsigned long, int __user*);
#asmlinkage long sys_clone(unsigned long, unsigned long, int, int __user*, int __user*, unsigned long);
#asmlinkage long sys_clone(unsigned long, unsigned long, int __user*, int __user*, unsigned long);
asmlinkage long sys_clone3(struct clone_args __user* uargs, size_t size);
asmlinkage long sys_execve(const char __user* filename, const char __user* const __user* argv, const char __user* const __user* envp);
asmlinkage long sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice);
asmlinkage long sys_swapon(const char __user* specialfile, int swap_flags);
asmlinkage long sys_swapoff(const char __user* specialfile);
asmlinkage long sys_mprotect(unsigned long start, size_t len, unsigned long prot);
asmlinkage long sys_msync(unsigned long start, size_t len, int flags);
asmlinkage long sys_mlock(unsigned long start, size_t len);
asmlinkage long sys_munlock(unsigned long start, size_t len);
asmlinkage long sys_mlockall(int flags);
asmlinkage long sys_munlockall(void);
asmlinkage long sys_mincore(unsigned long start, size_t len, unsigned char __user* vec);
asmlinkage long sys_madvise(unsigned long start, size_t len, int behavior);
asmlinkage long sys_process_madvise(int pidfd, const struct iovec __user* vec, size_t vlen, int behavior, unsigned int flags);
asmlinkage long sys_process_mrelease(int pidfd, unsigned int flags);
asmlinkage long sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
asmlinkage long sys_mseal(unsigned long start, size_t len, unsigned long flags);
asmlinkage long sys_mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user* nmask, unsigned long maxnode, unsigned flags);
asmlinkage long sys_get_mempolicy(int __user* policy, unsigned long __user* nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
asmlinkage long sys_set_mempolicy(int mode, const unsigned long __user* nmask, unsigned long maxnode);
asmlinkage long sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user* from, const unsigned long __user* to);
asmlinkage long sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user * pages, const int __user* nodes, int __user* status, int flags);
asmlinkage long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t __user* uinfo);
asmlinkage long sys_perf_event_open(struct perf_event_attr __user* attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
!asmlinkage long sys_accept4(int fd, struct sockaddr __user* upeer_sockaddr, int __user* upeer_addrlen, int flags);
asmlinkage long sys_recvmmsg(int fd, struct mmsghdr __user* msg, unsigned int vlen, unsigned flags, struct __kernel_timespec __user* timeout);
asmlinkage long sys_recvmmsg_time32(int fd, struct mmsghdr __user* msg, unsigned int vlen, unsigned flags, struct old_timespec32 __user* timeout);
asmlinkage long sys_wait4(pid_t pid, int __user* stat_addr, int options, struct rusage __user* ru);
asmlinkage long sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user* new_rlim, struct rlimit64 __user* old_rlim);
asmlinkage long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);
#asmlinkage long sys_fanotify_mark(int fanotify_fd, unsigned int flags, unsigned int mask_1, unsigned int mask_2, int dfd, const char __user* pathname);
#asmlinkage long sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user* pathname);
asmlinkage long sys_name_to_handle_at(int dfd, const char __user* name, struct file_handle __user* handle, void __user* mnt_id, int flag);
asmlinkage long sys_open_by_handle_at(int mountdirfd, struct file_handle __user* handle, int flags);
asmlinkage long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex __user* tx);
asmlinkage long sys_clock_adjtime32(clockid_t which_clock, struct old_timex32 __user* tx);
asmlinkage long sys_syncfs(int fd);
asmlinkage long sys_setns(int fd, int nstype);
asmlinkage long sys_pidfd_open(pid_t pid, unsigned int flags);
asmlinkage long sys_sendmmsg(int fd, struct mmsghdr __user* msg, unsigned int vlen, unsigned flags);
asmlinkage long sys_process_vm_readv(pid_t pid, const struct iovec __user* lvec, unsigned long liovcnt, const struct iovec __user* rvec, unsigned long riovcnt, unsigned long flags);
asmlinkage long sys_process_vm_writev(pid_t pid, const struct iovec __user* lvec, unsigned long liovcnt, const struct iovec __user* rvec, unsigned long riovcnt, unsigned long flags);
asmlinkage long sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
asmlinkage long sys_finit_module(int fd, const char __user* uargs, int flags);
asmlinkage long sys_sched_setattr(pid_t pid, struct sched_attr __user* attr, unsigned int flags);
asmlinkage long sys_sched_getattr(pid_t pid, struct sched_attr __user* attr, unsigned int size, unsigned int flags);
asmlinkage long sys_renameat2(int olddfd, const char __user* oldname, int newdfd, const char __user* newname, unsigned int flags);
asmlinkage long sys_seccomp(unsigned int op, unsigned int flags, void __user* uargs);
asmlinkage long sys_getrandom(char __user* buf, size_t count, unsigned int flags);
asmlinkage long sys_memfd_create(const char __user* uname_ptr, unsigned int flags);
asmlinkage long sys_bpf(int cmd, union bpf_attr __user* attr, unsigned int size);
asmlinkage long sys_execveat(int dfd, const char __user* filename, const char __user* const __user* argv, const char __user* const __user* envp, int flags);
asmlinkage long sys_userfaultfd(int flags);
asmlinkage long sys_membarrier(int cmd, unsigned int flags, int cpu_id);
asmlinkage long sys_mlock2(unsigned long start, size_t len, int flags);
asmlinkage long sys_copy_file_range(int fd_in, loff_t __user* off_in, int fd_out, loff_t __user* off_out, size_t len, unsigned int flags);
asmlinkage long sys_preadv2(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
asmlinkage long sys_pwritev2(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
asmlinkage long sys_pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);
asmlinkage long sys_pkey_alloc(unsigned long flags, unsigned long init_val);
asmlinkage long sys_pkey_free(int pkey);
asmlinkage long sys_statx(int dfd, const char __user* path, unsigned flags, unsigned mask, struct statx __user* buffer);
asmlinkage long sys_rseq(struct rseq __user* rseq, uint32_t rseq_len, int flags, uint32_t sig);
asmlinkage long sys_rseq_slice_yield(void);
asmlinkage long sys_open_tree(int dfd, const char __user* path, unsigned flags);
asmlinkage long sys_open_tree_attr(int dfd, const char __user* path, unsigned flags, struct mount_attr __user* uattr, size_t usize);
asmlinkage long sys_move_mount(int from_dfd, const char __user* from_path, int to_dfd, const char __user* to_path, unsigned int ms_flags);
asmlinkage long sys_mount_setattr(int dfd, const char __user* path, unsigned int flags, struct mount_attr __user* uattr, size_t usize);
asmlinkage long sys_fsopen(const char __user* fs_name, unsigned int flags);
asmlinkage long sys_fsconfig(int fs_fd, unsigned int cmd, const char __user* key, const void __user* value, int aux);
asmlinkage long sys_fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);
asmlinkage long sys_fspick(int dfd, const char __user* path, unsigned int flags);
asmlinkage long sys_pidfd_send_signal(int pidfd, int sig, siginfo_t __user* info, unsigned int flags);
asmlinkage long sys_pidfd_getfd(int pidfd, int fd, unsigned int flags);
asmlinkage long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user* attr, size_t size, __u32 flags);
asmlinkage long sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void __user* rule_attr, __u32 flags);
asmlinkage long sys_landlock_restrict_self(int ruleset_fd, __u32 flags);
asmlinkage long sys_memfd_secret(unsigned int flags);
asmlinkage long sys_set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
asmlinkage long sys_cachestat(unsigned int fd, struct cachestat_range __user* cstat_range, struct cachestat __user* cstat, unsigned int flags);
asmlinkage long sys_map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);
asmlinkage long sys_lsm_get_self_attr(unsigned int attr, struct lsm_ctx __user* ctx, u32 __user* size, u32 flags);
asmlinkage long sys_lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user* ctx, u32 size, u32 flags);
asmlinkage long sys_lsm_list_modules(u64 __user* ids, u32 __user* size, u32 flags);
asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int on);
asmlinkage long sys_uretprobe(void);
asmlinkage long sys_uprobe(void);
asmlinkage long sys_pciconfig_read(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user* buf);
asmlinkage long sys_pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user* buf);
asmlinkage long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn);
asmlinkage long sys_spu_run(int fd, __u32 __user* unpc, __u32 __user* ustatus);
asmlinkage long sys_spu_create(const char __user* name, unsigned int flags, umode_t mode, int fd);
asmlinkage long sys_open(const char __user* filename, int flags, umode_t mode);
asmlinkage long sys_link(const char __user* oldname, const char __user* newname);
asmlinkage long sys_unlink(const char __user* pathname);
asmlinkage long sys_mknod(const char __user* filename, umode_t mode, unsigned dev);
asmlinkage long sys_chmod(const char __user* filename, umode_t mode);
asmlinkage long sys_chown(const char __user* filename, uid_t user, gid_t group);
asmlinkage long sys_mkdir(const char __user* pathname, umode_t mode);
asmlinkage long sys_rmdir(const char __user* pathname);
asmlinkage long sys_lchown(const char __user* filename, uid_t user, gid_t group);
asmlinkage long sys_access(const char __user* filename, int mode);
asmlinkage long sys_rename(const char __user* oldname, const char __user* newname);
asmlinkage long sys_symlink(const char __user* old, const char __user* new);
asmlinkage long sys_stat64(const char __user* filename, struct stat64 __user* statbuf);
asmlinkage long sys_lstat64(const char __user* filename, struct stat64 __user* statbuf);
asmlinkage long sys_pipe(int __user* fildes);
asmlinkage long sys_dup2(unsigned int oldfd, unsigned int newfd);
asmlinkage long sys_epoll_create(int size);
asmlinkage long sys_inotify_init(void);
asmlinkage long sys_eventfd(unsigned int count);
asmlinkage long sys_signalfd(int ufd, sigset_t __user* user_mask, size_t sizemask);
asmlinkage long sys_sendfile(int out_fd, int in_fd, off_t __user* offset, size_t count);
asmlinkage long sys_newstat(const char __user* filename, struct stat __user* statbuf);
asmlinkage long sys_newlstat(const char __user* filename, struct stat __user* statbuf);
asmlinkage long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);
asmlinkage long sys_alarm(unsigned int seconds);
asmlinkage long sys_getpgrp(void);
asmlinkage long sys_pause(void);
asmlinkage long sys_time(__kernel_old_time_t __user* tloc);
asmlinkage long sys_time32(old_time32_t __user* tloc);
asmlinkage long sys_utime(char __user* filename, struct utimbuf __user* times);
asmlinkage long sys_utimes(char __user* filename, struct __kernel_old_timeval __user* utimes);
asmlinkage long sys_futimesat(int dfd, const char __user* filename, struct __kernel_old_timeval __user* utimes);
asmlinkage long sys_futimesat_time32(unsigned int dfd, const char __user* filename, struct old_timeval32 __user* t);
asmlinkage long sys_utime32(const char __user* filename, struct old_utimbuf32 __user* t);
asmlinkage long sys_utimes_time32(const char __user* filename, struct old_timeval32 __user* t);
asmlinkage long sys_creat(const char __user* pathname, umode_t mode);
asmlinkage long sys_getdents(unsigned int fd, struct linux_dirent __user* dirent, unsigned int count);
asmlinkage long sys_select(int n, fd_set __user* inp, fd_set __user* outp, fd_set __user* exp, struct __kernel_old_timeval __user* tvp);
asmlinkage long sys_poll(struct pollfd __user* ufds, unsigned int nfds, int timeout);
asmlinkage long sys_epoll_wait(int epfd, struct epoll_event __user* events, int maxevents, int timeout);
asmlinkage long sys_ustat(unsigned dev, struct ustat __user* ubuf);
asmlinkage long sys_vfork(void);
asmlinkage long sys_recv(int, void __user*, size_t, unsigned);
asmlinkage long sys_send(int, void __user*, size_t, unsigned);
asmlinkage long sys_oldumount(char __user* name);
asmlinkage long sys_uselib(const char __user* library);
asmlinkage long sys_sysfs(int option, unsigned long arg1, unsigned long arg2);
asmlinkage long sys_fork(void);
asmlinkage long sys_stime(__kernel_old_time_t __user* tptr);
asmlinkage long sys_stime32(old_time32_t __user* tptr);
asmlinkage long sys_sigpending(old_sigset_t __user* uset);
asmlinkage long sys_sigprocmask(int how, old_sigset_t __user* set, old_sigset_t __user* oset);
asmlinkage long sys_sigsuspend(old_sigset_t mask);
#asmlinkage long sys_sigsuspend(int unused1, int unused2, old_sigset_t mask);
asmlinkage long sys_sigaction(int, const struct old_sigaction __user*, struct old_sigaction __user*);
asmlinkage long sys_sgetmask(void);
asmlinkage long sys_ssetmask(int newmask);
asmlinkage long sys_signal(int sig, __sighandler_t handler);
asmlinkage long sys_nice(int increment);
asmlinkage long sys_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user* cmdline_ptr, unsigned long flags);
asmlinkage long sys_waitpid(pid_t pid, int __user* stat_addr, int options);
asmlinkage long sys_chown16(const char __user* filename, old_uid_t user, old_gid_t group);
asmlinkage long sys_lchown16(const char __user* filename, old_uid_t user, old_gid_t group);
asmlinkage long sys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group);
asmlinkage long sys_setregid16(old_gid_t rgid, old_gid_t egid);
asmlinkage long sys_setgid16(old_gid_t gid);
asmlinkage long sys_setreuid16(old_uid_t ruid, old_uid_t euid);
asmlinkage long sys_setuid16(old_uid_t uid);
asmlinkage long sys_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid);
asmlinkage long sys_getresuid16(old_uid_t __user* ruid, old_uid_t __user* euid, old_uid_t __user* suid);
asmlinkage long sys_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid);
asmlinkage long sys_getresgid16(old_gid_t __user* rgid, old_gid_t __user* egid, old_gid_t __user* sgid);
asmlinkage long sys_setfsuid16(old_uid_t uid);
asmlinkage long sys_setfsgid16(old_gid_t gid);
asmlinkage long sys_getgroups16(int gidsetsize, old_gid_t __user* grouplist);
asmlinkage long sys_setgroups16(int gidsetsize, old_gid_t __user* grouplist);
asmlinkage long sys_getuid16(void);
asmlinkage long sys_geteuid16(void);
asmlinkage long sys_getgid16(void);
asmlinkage long sys_getegid16(void);
asmlinkage long sys_socketcall(int call, unsigned long __user* args);
asmlinkage long sys_stat(const char __user* filename, struct __old_kernel_stat __user* statbuf);
asmlinkage long sys_lstat(const char __user* filename, struct __old_kernel_stat __user* statbuf);
asmlinkage long sys_fstat(unsigned int fd, struct __old_kernel_stat __user* statbuf);
asmlinkage long sys_readlink(const char __user* path, char __user* buf, int bufsiz);
asmlinkage long sys_old_select(struct sel_arg_struct __user* arg);
asmlinkage long sys_old_readdir(unsigned int, struct old_linux_dirent __user*, unsigned int);
asmlinkage long sys_gethostname(char __user* name, int len);
asmlinkage long sys_uname(struct old_utsname __user*);
asmlinkage long sys_olduname(struct oldold_utsname __user*);
asmlinkage long sys_old_getrlimit(unsigned int resource, struct rlimit __user* rlim);
asmlinkage long sys_ipc(unsigned int call, int first, unsigned long second, unsigned long third, void __user* ptr, long fifth);
asmlinkage long sys_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
asmlinkage long sys_old_mmap(struct mmap_arg_struct __user* arg);
#asmlinkage long sys_ni_syscall(void);
asmlinkage long sys_ni_posix_timers(void);
"""


# include/linux/compat.h
syscall_defs_compat = """
asmlinkage long compat_sys_io_setup(unsigned nr_reqs, u32 __user* ctx32p);
asmlinkage long compat_sys_io_submit(compat_aio_context_t ctx_id, int nr, u32 __user* iocb);
!asmlinkage long compat_sys_io_pgetevents(compat_aio_context_t ctx_id, compat_long_t min_nr, compat_long_t nr, struct io_event __user* events, struct old_timespec32 __user* timeout, const struct __compat_aio_sigset __user* usig); # codespell:ignore
!asmlinkage long compat_sys_io_pgetevents_time64(compat_aio_context_t ctx_id, compat_long_t min_nr, compat_long_t nr, struct io_event __user* events, struct __kernel_timespec __user* timeout, const struct __compat_aio_sigset __user* usig); # codespell:ignore
asmlinkage long compat_sys_epoll_pwait(int epfd, struct epoll_event __user* events, int maxevents, int timeout, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize);
asmlinkage long compat_sys_epoll_pwait2(int epfd, struct epoll_event __user* events, int maxevents, const struct __kernel_timespec __user* timeout, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize);
asmlinkage long compat_sys_fcntl(unsigned int fd, unsigned int cmd, compat_ulong_t arg);
asmlinkage long compat_sys_fcntl64(unsigned int fd, unsigned int cmd, compat_ulong_t arg);
asmlinkage long compat_sys_ioctl(unsigned int fd, unsigned int cmd, compat_ulong_t arg);
asmlinkage long compat_sys_statfs(const char __user* pathname, struct compat_statfs __user* buf);
asmlinkage long compat_sys_statfs64(const char __user* pathname, compat_size_t sz, struct compat_statfs64 __user* buf);
asmlinkage long compat_sys_fstatfs(unsigned int fd, struct compat_statfs __user* buf);
asmlinkage long compat_sys_fstatfs64(unsigned int fd, compat_size_t sz, struct compat_statfs64 __user* buf);
asmlinkage long compat_sys_truncate(const char __user*, compat_off_t);
asmlinkage long compat_sys_ftruncate(unsigned int, compat_off_t);
asmlinkage long compat_sys_openat(int dfd, const char __user* filename, int flags, umode_t mode);
asmlinkage long compat_sys_getdents(unsigned int fd, struct compat_linux_dirent __user* dirent, unsigned int count);
asmlinkage long compat_sys_lseek(unsigned int, compat_off_t, unsigned int);
asmlinkage ssize_t compat_sys_preadv(compat_ulong_t fd, const struct iovec __user* vec, compat_ulong_t vlen, u32 pos_low, u32 pos_high);
asmlinkage ssize_t compat_sys_pwritev(compat_ulong_t fd, const struct iovec __user* vec, compat_ulong_t vlen, u32 pos_low, u32 pos_high);
asmlinkage long compat_sys_preadv64(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, loff_t pos);
asmlinkage long compat_sys_pwritev64(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, loff_t pos);
asmlinkage long compat_sys_sendfile(int out_fd, int in_fd, compat_off_t __user* offset, compat_size_t count);
asmlinkage long compat_sys_sendfile64(int out_fd, int in_fd, compat_loff_t __user* offset, compat_size_t count);
asmlinkage long compat_sys_pselect6_time32(int n, compat_ulong_t __user* inp, compat_ulong_t __user* outp, compat_ulong_t __user* exp, struct old_timespec32 __user* tsp, void __user* sig);
asmlinkage long compat_sys_pselect6_time64(int n, compat_ulong_t __user* inp, compat_ulong_t __user* outp, compat_ulong_t __user* exp, struct __kernel_timespec __user* tsp, void __user* sig);
asmlinkage long compat_sys_ppoll_time32(struct pollfd __user* ufds, unsigned int nfds, struct old_timespec32 __user* tsp, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize);
asmlinkage long compat_sys_ppoll_time64(struct pollfd __user* ufds, unsigned int nfds, struct __kernel_timespec __user* tsp, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize);
asmlinkage long compat_sys_signalfd4(int ufd, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize, int flags);
asmlinkage long compat_sys_newfstatat(unsigned int dfd, const char __user* filename, struct compat_stat __user* statbuf, int flag);
asmlinkage long compat_sys_newfstat(unsigned int fd, struct compat_stat __user* statbuf);
!asmlinkage long compat_sys_waitid(int which, compat_pid_t pid, struct compat_siginfo __user* waitid, int options, struct compat_rusage __user* uru);
asmlinkage long compat_sys_set_robust_list(struct compat_robust_list_head __user* head, compat_size_t len);
asmlinkage long compat_sys_get_robust_list(int pid, compat_uptr_t __user* head_ptr, compat_size_t __user* len_ptr);
asmlinkage long compat_sys_getitimer(int which, struct old_itimerval32 __user* it);
asmlinkage long compat_sys_setitimer(int which, struct old_itimerval32 __user* in, struct old_itimerval32 __user* out);
!asmlinkage long compat_sys_kexec_load(compat_ulong_t entry, compat_ulong_t nr_segments, struct compat_kexec_segment __user* segments, compat_ulong_t flags);
asmlinkage long compat_sys_timer_create(clockid_t which_clock, struct compat_sigevent __user* timer_event_spec, timer_t __user* created_timer_id);
asmlinkage long compat_sys_ptrace(compat_long_t request, compat_long_t pid, compat_long_t addr, compat_long_t data);
asmlinkage long compat_sys_sched_setaffinity(compat_pid_t pid, unsigned int len, compat_ulong_t __user* user_mask_ptr);
asmlinkage long compat_sys_sched_getaffinity(compat_pid_t pid, unsigned int len, compat_ulong_t __user* user_mask_ptr);
asmlinkage long compat_sys_sigaltstack(const compat_stack_t __user* uss_ptr, compat_stack_t __user* uoss_ptr);
asmlinkage long compat_sys_rt_sigsuspend(compat_sigset_t __user* unewset, compat_size_t sigsetsize);
!asmlinkage long compat_sys_rt_sigaction(int sig, const struct compat_sigaction __user* act, struct compat_sigaction __user* oact, compat_size_t sigsetsize);
asmlinkage long compat_sys_rt_sigprocmask(int how, compat_sigset_t __user* set, compat_sigset_t __user* oset, compat_size_t sigsetsize);
asmlinkage long compat_sys_rt_sigpending(compat_sigset_t __user* uset, compat_size_t sigsetsize);
asmlinkage long compat_sys_rt_sigtimedwait_time32(compat_sigset_t __user* uthese, struct compat_siginfo __user* uinfo, struct old_timespec32 __user* uts, compat_size_t sigsetsize);
asmlinkage long compat_sys_rt_sigtimedwait_time64(compat_sigset_t __user* uthese, struct compat_siginfo __user* uinfo, struct __kernel_timespec __user* uts, compat_size_t sigsetsize);
asmlinkage long compat_sys_rt_sigqueueinfo(compat_pid_t pid, int sig, struct compat_siginfo __user* uinfo);
asmlinkage long compat_sys_times(struct compat_tms __user* tbuf);
asmlinkage long compat_sys_getrlimit(unsigned int resource, struct compat_rlimit __user* rlim);
asmlinkage long compat_sys_setrlimit(unsigned int resource, struct compat_rlimit __user* rlim);
asmlinkage long compat_sys_getrusage(int who, struct compat_rusage __user* ru);
asmlinkage long compat_sys_gettimeofday(struct old_timeval32 __user* tv, struct timezone __user* tz);
asmlinkage long compat_sys_settimeofday(struct old_timeval32 __user* tv, struct timezone __user* tz);
asmlinkage long compat_sys_sysinfo(struct compat_sysinfo __user* info);
asmlinkage long compat_sys_mq_open(const char __user* u_name, int oflag, compat_mode_t mode, struct compat_mq_attr __user* u_attr);
asmlinkage long compat_sys_mq_notify(mqd_t mqdes, const struct compat_sigevent __user* u_notification);
asmlinkage long compat_sys_mq_getsetattr(mqd_t mqdes, const struct compat_mq_attr __user* u_mqstat, struct compat_mq_attr __user* u_omqstat);
asmlinkage long compat_sys_msgctl(int first, int second, void __user* uptr);
asmlinkage long compat_sys_msgrcv(int msqid, compat_uptr_t msgp, compat_ssize_t msgsz, compat_long_t msgtyp, int msgflg);
asmlinkage long compat_sys_msgsnd(int msqid, compat_uptr_t msgp, compat_ssize_t msgsz, int msgflg);
asmlinkage long compat_sys_semctl(int semid, int semnum, int cmd, int arg);
asmlinkage long compat_sys_shmctl(int first, int second, void __user* uptr);
asmlinkage long compat_sys_shmat(int shmid, compat_uptr_t shmaddr, int shmflg);
asmlinkage long compat_sys_recvfrom(int fd, void __user* buf, compat_size_t len, unsigned flags, struct sockaddr __user* addr, int __user* addrlen);
asmlinkage long compat_sys_sendmsg(int fd, struct compat_msghdr __user* msg, unsigned flags);
asmlinkage long compat_sys_recvmsg(int fd, struct compat_msghdr __user* msg, unsigned int flags);
asmlinkage long compat_sys_keyctl(u32 option, u32 arg2, u32 arg3, u32 arg4, u32 arg5);
asmlinkage long compat_sys_execve(const char __user* filename, const compat_uptr_t __user* argv, const compat_uptr_t __user* envp);
asmlinkage long compat_sys_rt_tgsigqueueinfo(compat_pid_t tgid, compat_pid_t pid, int sig, struct compat_siginfo __user* uinfo);
asmlinkage long compat_sys_recvmmsg_time64(int fd, struct compat_mmsghdr __user* mmsg, unsigned vlen, unsigned int flags, struct __kernel_timespec __user* timeout);
asmlinkage long compat_sys_recvmmsg_time32(int fd, struct compat_mmsghdr __user* mmsg, unsigned vlen, unsigned int flags, struct old_timespec32 __user* timeout);
asmlinkage long compat_sys_wait4(compat_pid_t pid, compat_uint_t __user* stat_addr, int options, struct compat_rusage __user* ru);
!asmlinkage long compat_sys_fanotify_mark(int fanotify_fd, unsigned int flags, __u32 mask_1, __u32 mask_2, int dfd, const char __user* pathname);
asmlinkage long compat_sys_open_by_handle_at(int mountdirfd, struct file_handle __user* handle, int flags);
asmlinkage long compat_sys_sendmmsg(int fd, struct compat_mmsghdr __user* mmsg, unsigned vlen, unsigned int flags);
asmlinkage long compat_sys_execveat(int dfd, const char __user* filename, const compat_uptr_t __user* argv, const compat_uptr_t __user* envp, int flags);
asmlinkage ssize_t compat_sys_preadv2(compat_ulong_t fd, const struct iovec __user* vec, compat_ulong_t vlen, u32 pos_low, u32 pos_high, rwf_t flags);
asmlinkage ssize_t compat_sys_pwritev2(compat_ulong_t fd, const struct iovec __user* vec, compat_ulong_t vlen, u32 pos_low, u32 pos_high, rwf_t flags);
asmlinkage long compat_sys_preadv64v2(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, loff_t pos, rwf_t flags);
asmlinkage long compat_sys_pwritev64v2(unsigned long fd, const struct iovec __user* vec, unsigned long vlen, loff_t pos, rwf_t flags);
asmlinkage long compat_sys_open(const char __user* filename, int flags, umode_t mode);
asmlinkage long compat_sys_signalfd(int ufd, const compat_sigset_t __user* sigmask, compat_size_t sigsetsize);
asmlinkage long compat_sys_newstat(const char __user* filename, struct compat_stat __user* statbuf);
asmlinkage long compat_sys_newlstat(const char __user* filename, struct compat_stat __user* statbuf);
asmlinkage long compat_sys_select(int n, compat_ulong_t __user* inp, compat_ulong_t __user* outp, compat_ulong_t __user* exp, struct old_timeval32 __user* tvp);
asmlinkage long compat_sys_ustat(unsigned dev, struct compat_ustat __user* u32);
asmlinkage long compat_sys_recv(int fd, void __user* buf, compat_size_t len, unsigned flags);
asmlinkage long compat_sys_old_readdir(unsigned int fd, struct compat_old_linux_dirent __user*, unsigned int count);
asmlinkage long compat_sys_old_select(struct compat_sel_arg_struct __user* arg);
asmlinkage long compat_sys_ipc(u32, int, int, u32, compat_uptr_t, u32);
asmlinkage long compat_sys_sigpending(compat_old_sigset_t __user* set);
asmlinkage long compat_sys_sigprocmask(int how, compat_old_sigset_t __user* nset, compat_old_sigset_t __user* oset);
asmlinkage long compat_sys_sigaction(int sig, const struct compat_old_sigaction __user* act, struct compat_old_sigaction __user* oact);
asmlinkage long compat_sys_socketcall(int call, u32 __user* args);
asmlinkage long compat_sys_truncate64(const char __user* pathname, compat_arg_u64(len));
asmlinkage long compat_sys_ftruncate64(unsigned int fd, compat_arg_u64(len));
asmlinkage long compat_sys_fallocate(int fd, int mode, compat_arg_u64(offset), compat_arg_u64(len));
asmlinkage long compat_sys_pread64(unsigned int fd, char __user* buf, size_t count, compat_arg_u64(pos));
asmlinkage long compat_sys_pwrite64(unsigned int fd, const char __user* buf, size_t count, compat_arg_u64(pos));
asmlinkage long compat_sys_sync_file_range(int fd, compat_arg_u64(pos), compat_arg_u64(nbytes), unsigned int flags);
asmlinkage long compat_sys_fadvise64_64(int fd, compat_arg_u64(pos), compat_arg_u64(len), int advice);
asmlinkage long compat_sys_readahead(int fd, compat_arg_u64(offset), size_t count);
"""


# x86_64
# - arch/x86/entry/syscalls/syscall_64.tbl
x64_syscall_tbl = """
0       common  read                    sys_read
1       common  write                   sys_write
2       common  open                    sys_open
3       common  close                   sys_close
4       common  stat                    sys_newstat
5       common  fstat                   sys_newfstat
6       common  lstat                   sys_newlstat
7       common  poll                    sys_poll
8       common  lseek                   sys_lseek
9       common  mmap                    sys_mmap
10      common  mprotect                sys_mprotect
11      common  munmap                  sys_munmap
12      common  brk                     sys_brk
13      64      rt_sigaction            sys_rt_sigaction
14      common  rt_sigprocmask          sys_rt_sigprocmask
15      64      rt_sigreturn            sys_rt_sigreturn
16      64      ioctl                   sys_ioctl
17      common  pread64                 sys_pread64
18      common  pwrite64                sys_pwrite64
19      64      readv                   sys_readv
20      64      writev                  sys_writev
21      common  access                  sys_access
22      common  pipe                    sys_pipe
23      common  select                  sys_select
24      common  sched_yield             sys_sched_yield
25      common  mremap                  sys_mremap
26      common  msync                   sys_msync
27      common  mincore                 sys_mincore
28      common  madvise                 sys_madvise
29      common  shmget                  sys_shmget
30      common  shmat                   sys_shmat
31      common  shmctl                  sys_shmctl
32      common  dup                     sys_dup
33      common  dup2                    sys_dup2
34      common  pause                   sys_pause
35      common  nanosleep               sys_nanosleep
36      common  getitimer               sys_getitimer
37      common  alarm                   sys_alarm
38      common  setitimer               sys_setitimer
39      common  getpid                  sys_getpid
40      common  sendfile                sys_sendfile64
41      common  socket                  sys_socket
42      common  connect                 sys_connect
43      common  accept                  sys_accept
44      common  sendto                  sys_sendto
45      64      recvfrom                sys_recvfrom
46      64      sendmsg                 sys_sendmsg
47      64      recvmsg                 sys_recvmsg
48      common  shutdown                sys_shutdown
49      common  bind                    sys_bind
50      common  listen                  sys_listen
51      common  getsockname             sys_getsockname
52      common  getpeername             sys_getpeername
53      common  socketpair              sys_socketpair
54      64      setsockopt              sys_setsockopt
55      64      getsockopt              sys_getsockopt
56      common  clone                   sys_clone
57      common  fork                    sys_fork
58      common  vfork                   sys_vfork
59      64      execve                  sys_execve
60      common  exit                    sys_exit                        -                       noreturn
61      common  wait4                   sys_wait4
62      common  kill                    sys_kill
63      common  uname                   sys_newuname
64      common  semget                  sys_semget
65      common  semop                   sys_semop
66      common  semctl                  sys_semctl
67      common  shmdt                   sys_shmdt
68      common  msgget                  sys_msgget
69      common  msgsnd                  sys_msgsnd
70      common  msgrcv                  sys_msgrcv
71      common  msgctl                  sys_msgctl
72      common  fcntl                   sys_fcntl
73      common  flock                   sys_flock
74      common  fsync                   sys_fsync
75      common  fdatasync               sys_fdatasync
76      common  truncate                sys_truncate
77      common  ftruncate               sys_ftruncate
78      common  getdents                sys_getdents
79      common  getcwd                  sys_getcwd
80      common  chdir                   sys_chdir
81      common  fchdir                  sys_fchdir
82      common  rename                  sys_rename
83      common  mkdir                   sys_mkdir
84      common  rmdir                   sys_rmdir
85      common  creat                   sys_creat
86      common  link                    sys_link
87      common  unlink                  sys_unlink
88      common  symlink                 sys_symlink
89      common  readlink                sys_readlink
90      common  chmod                   sys_chmod
91      common  fchmod                  sys_fchmod
92      common  chown                   sys_chown
93      common  fchown                  sys_fchown
94      common  lchown                  sys_lchown
95      common  umask                   sys_umask
96      common  gettimeofday            sys_gettimeofday
97      common  getrlimit               sys_getrlimit
98      common  getrusage               sys_getrusage
99      common  sysinfo                 sys_sysinfo
100     common  times                   sys_times
101     64      ptrace                  sys_ptrace
102     common  getuid                  sys_getuid
103     common  syslog                  sys_syslog
104     common  getgid                  sys_getgid
105     common  setuid                  sys_setuid
106     common  setgid                  sys_setgid
107     common  geteuid                 sys_geteuid
108     common  getegid                 sys_getegid
109     common  setpgid                 sys_setpgid
110     common  getppid                 sys_getppid
111     common  getpgrp                 sys_getpgrp
112     common  setsid                  sys_setsid
113     common  setreuid                sys_setreuid
114     common  setregid                sys_setregid
115     common  getgroups               sys_getgroups
116     common  setgroups               sys_setgroups
117     common  setresuid               sys_setresuid
118     common  getresuid               sys_getresuid
119     common  setresgid               sys_setresgid
120     common  getresgid               sys_getresgid
121     common  getpgid                 sys_getpgid
122     common  setfsuid                sys_setfsuid
123     common  setfsgid                sys_setfsgid
124     common  getsid                  sys_getsid
125     common  capget                  sys_capget
126     common  capset                  sys_capset
127     64      rt_sigpending           sys_rt_sigpending
128     64      rt_sigtimedwait         sys_rt_sigtimedwait
129     64      rt_sigqueueinfo         sys_rt_sigqueueinfo
130     common  rt_sigsuspend           sys_rt_sigsuspend
131     64      sigaltstack             sys_sigaltstack
132     common  utime                   sys_utime
133     common  mknod                   sys_mknod
134     64      uselib
135     common  personality             sys_personality
136     common  ustat                   sys_ustat
137     common  statfs                  sys_statfs
138     common  fstatfs                 sys_fstatfs
139     common  sysfs                   sys_sysfs
140     common  getpriority             sys_getpriority
141     common  setpriority             sys_setpriority
142     common  sched_setparam          sys_sched_setparam
143     common  sched_getparam          sys_sched_getparam
144     common  sched_setscheduler      sys_sched_setscheduler
145     common  sched_getscheduler      sys_sched_getscheduler
146     common  sched_get_priority_max  sys_sched_get_priority_max
147     common  sched_get_priority_min  sys_sched_get_priority_min
148     common  sched_rr_get_interval   sys_sched_rr_get_interval
149     common  mlock                   sys_mlock
150     common  munlock                 sys_munlock
151     common  mlockall                sys_mlockall
152     common  munlockall              sys_munlockall
153     common  vhangup                 sys_vhangup
154     common  modify_ldt              sys_modify_ldt
155     common  pivot_root              sys_pivot_root
156     64      _sysctl                 sys_ni_syscall
157     common  prctl                   sys_prctl
158     common  arch_prctl              sys_arch_prctl
159     common  adjtimex                sys_adjtimex
160     common  setrlimit               sys_setrlimit
161     common  chroot                  sys_chroot
162     common  sync                    sys_sync
163     common  acct                    sys_acct
164     common  settimeofday            sys_settimeofday
165     common  mount                   sys_mount
166     common  umount2                 sys_umount
167     common  swapon                  sys_swapon
168     common  swapoff                 sys_swapoff
169     common  reboot                  sys_reboot
170     common  sethostname             sys_sethostname
171     common  setdomainname           sys_setdomainname
172     common  iopl                    sys_iopl
173     common  ioperm                  sys_ioperm
174     64      create_module
175     common  init_module             sys_init_module
176     common  delete_module           sys_delete_module
177     64      get_kernel_syms
178     64      query_module
179     common  quotactl                sys_quotactl
180     64      nfsservctl
181     common  getpmsg
182     common  putpmsg
183     common  afs_syscall
184     common  tuxcall
185     common  security
186     common  gettid                  sys_gettid
187     common  readahead               sys_readahead
188     common  setxattr                sys_setxattr
189     common  lsetxattr               sys_lsetxattr
190     common  fsetxattr               sys_fsetxattr
191     common  getxattr                sys_getxattr
192     common  lgetxattr               sys_lgetxattr
193     common  fgetxattr               sys_fgetxattr
194     common  listxattr               sys_listxattr
195     common  llistxattr              sys_llistxattr
196     common  flistxattr              sys_flistxattr
197     common  removexattr             sys_removexattr
198     common  lremovexattr            sys_lremovexattr
199     common  fremovexattr            sys_fremovexattr
200     common  tkill                   sys_tkill
201     common  time                    sys_time
202     common  futex                   sys_futex
203     common  sched_setaffinity       sys_sched_setaffinity
204     common  sched_getaffinity       sys_sched_getaffinity
205     64      set_thread_area
206     64      io_setup                sys_io_setup
207     common  io_destroy              sys_io_destroy
208     common  io_getevents            sys_io_getevents
209     64      io_submit               sys_io_submit
210     common  io_cancel               sys_io_cancel
211     64      get_thread_area
212     common  lookup_dcookie
213     common  epoll_create            sys_epoll_create
214     64      epoll_ctl_old
215     64      epoll_wait_old
216     common  remap_file_pages        sys_remap_file_pages
217     common  getdents64              sys_getdents64
218     common  set_tid_address         sys_set_tid_address
219     common  restart_syscall         sys_restart_syscall
220     common  semtimedop              sys_semtimedop
221     common  fadvise64               sys_fadvise64
222     64      timer_create            sys_timer_create
223     common  timer_settime           sys_timer_settime
224     common  timer_gettime           sys_timer_gettime
225     common  timer_getoverrun        sys_timer_getoverrun
226     common  timer_delete            sys_timer_delete
227     common  clock_settime           sys_clock_settime
228     common  clock_gettime           sys_clock_gettime
229     common  clock_getres            sys_clock_getres
230     common  clock_nanosleep         sys_clock_nanosleep
231     common  exit_group              sys_exit_group                  -                       noreturn
232     common  epoll_wait              sys_epoll_wait
233     common  epoll_ctl               sys_epoll_ctl
234     common  tgkill                  sys_tgkill
235     common  utimes                  sys_utimes
236     64      vserver
237     common  mbind                   sys_mbind
238     common  set_mempolicy           sys_set_mempolicy
239     common  get_mempolicy           sys_get_mempolicy
240     common  mq_open                 sys_mq_open
241     common  mq_unlink               sys_mq_unlink
242     common  mq_timedsend            sys_mq_timedsend
243     common  mq_timedreceive         sys_mq_timedreceive
244     64      mq_notify               sys_mq_notify
245     common  mq_getsetattr           sys_mq_getsetattr
246     64      kexec_load              sys_kexec_load
247     64      waitid                  sys_waitid
248     common  add_key                 sys_add_key
249     common  request_key             sys_request_key
250     common  keyctl                  sys_keyctl
251     common  ioprio_set              sys_ioprio_set
252     common  ioprio_get              sys_ioprio_get
253     common  inotify_init            sys_inotify_init
254     common  inotify_add_watch       sys_inotify_add_watch
255     common  inotify_rm_watch        sys_inotify_rm_watch
256     common  migrate_pages           sys_migrate_pages
257     common  openat                  sys_openat
258     common  mkdirat                 sys_mkdirat
259     common  mknodat                 sys_mknodat
260     common  fchownat                sys_fchownat
261     common  futimesat               sys_futimesat
262     common  newfstatat              sys_newfstatat
263     common  unlinkat                sys_unlinkat
264     common  renameat                sys_renameat
265     common  linkat                  sys_linkat
266     common  symlinkat               sys_symlinkat
267     common  readlinkat              sys_readlinkat
268     common  fchmodat                sys_fchmodat
269     common  faccessat               sys_faccessat
270     common  pselect6                sys_pselect6
271     common  ppoll                   sys_ppoll
272     common  unshare                 sys_unshare
273     64      set_robust_list         sys_set_robust_list
274     64      get_robust_list         sys_get_robust_list
275     common  splice                  sys_splice
276     common  tee                     sys_tee
277     common  sync_file_range         sys_sync_file_range
278     64      vmsplice                sys_vmsplice
279     64      move_pages              sys_move_pages
280     common  utimensat               sys_utimensat
281     common  epoll_pwait             sys_epoll_pwait
282     common  signalfd                sys_signalfd
283     common  timerfd_create          sys_timerfd_create
284     common  eventfd                 sys_eventfd
285     common  fallocate               sys_fallocate
286     common  timerfd_settime         sys_timerfd_settime
287     common  timerfd_gettime         sys_timerfd_gettime
288     common  accept4                 sys_accept4
289     common  signalfd4               sys_signalfd4
290     common  eventfd2                sys_eventfd2
291     common  epoll_create1           sys_epoll_create1
292     common  dup3                    sys_dup3
293     common  pipe2                   sys_pipe2
294     common  inotify_init1           sys_inotify_init1
295     64      preadv                  sys_preadv
296     64      pwritev                 sys_pwritev
297     64      rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo
298     common  perf_event_open         sys_perf_event_open
299     64      recvmmsg                sys_recvmmsg
300     common  fanotify_init           sys_fanotify_init
301     common  fanotify_mark           sys_fanotify_mark
302     common  prlimit64               sys_prlimit64
303     common  name_to_handle_at       sys_name_to_handle_at
304     common  open_by_handle_at       sys_open_by_handle_at
305     common  clock_adjtime           sys_clock_adjtime
306     common  syncfs                  sys_syncfs
307     64      sendmmsg                sys_sendmmsg
308     common  setns                   sys_setns
309     common  getcpu                  sys_getcpu
310     64      process_vm_readv        sys_process_vm_readv
311     64      process_vm_writev       sys_process_vm_writev
312     common  kcmp                    sys_kcmp
313     common  finit_module            sys_finit_module
314     common  sched_setattr           sys_sched_setattr
315     common  sched_getattr           sys_sched_getattr
316     common  renameat2               sys_renameat2
317     common  seccomp                 sys_seccomp
318     common  getrandom               sys_getrandom
319     common  memfd_create            sys_memfd_create
320     common  kexec_file_load         sys_kexec_file_load
321     common  bpf                     sys_bpf
322     64      execveat                sys_execveat
323     common  userfaultfd             sys_userfaultfd
324     common  membarrier              sys_membarrier
325     common  mlock2                  sys_mlock2
326     common  copy_file_range         sys_copy_file_range
327     64      preadv2                 sys_preadv2
328     64      pwritev2                sys_pwritev2
329     common  pkey_mprotect           sys_pkey_mprotect
330     common  pkey_alloc              sys_pkey_alloc
331     common  pkey_free               sys_pkey_free
332     common  statx                   sys_statx
333     common  io_pgetevents           sys_io_pgetevents
334     common  rseq                    sys_rseq
335     common  uretprobe               sys_uretprobe
336     common  uprobe                  sys_uprobe
424     common  pidfd_send_signal       sys_pidfd_send_signal
425     common  io_uring_setup          sys_io_uring_setup
426     common  io_uring_enter          sys_io_uring_enter
427     common  io_uring_register       sys_io_uring_register
428     common  open_tree               sys_open_tree
429     common  move_mount              sys_move_mount
430     common  fsopen                  sys_fsopen
431     common  fsconfig                sys_fsconfig
432     common  fsmount                 sys_fsmount
433     common  fspick                  sys_fspick
434     common  pidfd_open              sys_pidfd_open
435     common  clone3                  sys_clone3
436     common  close_range             sys_close_range
437     common  openat2                 sys_openat2
438     common  pidfd_getfd             sys_pidfd_getfd
439     common  faccessat2              sys_faccessat2
440     common  process_madvise         sys_process_madvise
441     common  epoll_pwait2            sys_epoll_pwait2
442     common  mount_setattr           sys_mount_setattr
443     common  quotactl_fd             sys_quotactl_fd
444     common  landlock_create_ruleset sys_landlock_create_ruleset
445     common  landlock_add_rule       sys_landlock_add_rule
446     common  landlock_restrict_self  sys_landlock_restrict_self
447     common  memfd_secret            sys_memfd_secret
448     common  process_mrelease        sys_process_mrelease
449     common  futex_waitv             sys_futex_waitv
450     common  set_mempolicy_home_node sys_set_mempolicy_home_node
451     common  cachestat               sys_cachestat
452     common  fchmodat2               sys_fchmodat2
453     common  map_shadow_stack        sys_map_shadow_stack
454     common  futex_wake              sys_futex_wake
455     common  futex_wait              sys_futex_wait
456     common  futex_requeue           sys_futex_requeue
457     common  statmount               sys_statmount
458     common  listmount               sys_listmount
459     common  lsm_get_self_attr       sys_lsm_get_self_attr
460     common  lsm_set_self_attr       sys_lsm_set_self_attr
461     common  lsm_list_modules        sys_lsm_list_modules
462     common  mseal                   sys_mseal
463     common  setxattrat              sys_setxattrat
464     common  getxattrat              sys_getxattrat
465     common  listxattrat             sys_listxattrat
466     common  removexattrat           sys_removexattrat
467     common  open_tree_attr          sys_open_tree_attr
468     common  file_getattr            sys_file_getattr
469     common  file_setattr            sys_file_setattr
470     common  listns                  sys_listns
471     common  rseq_slice_yield        sys_rseq_slice_yield
512     x32     rt_sigaction            compat_sys_rt_sigaction
513     x32     rt_sigreturn            compat_sys_x32_rt_sigreturn
514     x32     ioctl                   compat_sys_ioctl
515     x32     readv                   sys_readv
516     x32     writev                  sys_writev
517     x32     recvfrom                compat_sys_recvfrom
518     x32     sendmsg                 compat_sys_sendmsg
519     x32     recvmsg                 compat_sys_recvmsg
520     x32     execve                  compat_sys_execve
521     x32     ptrace                  compat_sys_ptrace
522     x32     rt_sigpending           compat_sys_rt_sigpending
523     x32     rt_sigtimedwait         compat_sys_rt_sigtimedwait_time64
524     x32     rt_sigqueueinfo         compat_sys_rt_sigqueueinfo
525     x32     sigaltstack             compat_sys_sigaltstack
526     x32     timer_create            compat_sys_timer_create
527     x32     mq_notify               compat_sys_mq_notify
528     x32     kexec_load              compat_sys_kexec_load
529     x32     waitid                  compat_sys_waitid
530     x32     set_robust_list         compat_sys_set_robust_list
531     x32     get_robust_list         compat_sys_get_robust_list
532     x32     vmsplice                sys_vmsplice
533     x32     move_pages              sys_move_pages
534     x32     preadv                  compat_sys_preadv64
535     x32     pwritev                 compat_sys_pwritev64
536     x32     rt_tgsigqueueinfo       compat_sys_rt_tgsigqueueinfo
537     x32     recvmmsg                compat_sys_recvmmsg_time64
538     x32     sendmmsg                compat_sys_sendmmsg
539     x32     process_vm_readv        sys_process_vm_readv
540     x32     process_vm_writev       sys_process_vm_writev
541     x32     setsockopt              sys_setsockopt
542     x32     getsockopt              sys_getsockopt
543     x32     io_setup                compat_sys_io_setup
544     x32     io_submit               compat_sys_io_submit
545     x32     execveat                compat_sys_execveat
546     x32     preadv2                 compat_sys_preadv64v2
547     x32     pwritev2                compat_sys_pwritev64v2
"""


# i386 (native / compat(emulated))
# - arch/x86/entry/syscalls/syscall_32.tbl
x86_syscall_tbl = """
0       i386    restart_syscall         sys_restart_syscall
1       i386    exit                    sys_exit                        -                       noreturn
2       i386    fork                    sys_fork
3       i386    read                    sys_read
4       i386    write                   sys_write
5       i386    open                    sys_open                        compat_sys_open
6       i386    close                   sys_close
7       i386    waitpid                 sys_waitpid
8       i386    creat                   sys_creat
9       i386    link                    sys_link
10      i386    unlink                  sys_unlink
11      i386    execve                  sys_execve                      compat_sys_execve
12      i386    chdir                   sys_chdir
13      i386    time                    sys_time32
14      i386    mknod                   sys_mknod
15      i386    chmod                   sys_chmod
16      i386    lchown                  sys_lchown16
17      i386    break
18      i386    oldstat                 sys_stat
19      i386    lseek                   sys_lseek                       compat_sys_lseek
20      i386    getpid                  sys_getpid
21      i386    mount                   sys_mount
22      i386    umount                  sys_oldumount
23      i386    setuid                  sys_setuid16
24      i386    getuid                  sys_getuid16
25      i386    stime                   sys_stime32
26      i386    ptrace                  sys_ptrace                      compat_sys_ptrace
27      i386    alarm                   sys_alarm
28      i386    oldfstat                sys_fstat
29      i386    pause                   sys_pause
30      i386    utime                   sys_utime32
31      i386    stty
32      i386    gtty
33      i386    access                  sys_access
34      i386    nice                    sys_nice
35      i386    ftime
36      i386    sync                    sys_sync
37      i386    kill                    sys_kill
38      i386    rename                  sys_rename
39      i386    mkdir                   sys_mkdir
40      i386    rmdir                   sys_rmdir
41      i386    dup                     sys_dup
42      i386    pipe                    sys_pipe
43      i386    times                   sys_times                       compat_sys_times
44      i386    prof
45      i386    brk                     sys_brk
46      i386    setgid                  sys_setgid16
47      i386    getgid                  sys_getgid16
48      i386    signal                  sys_signal
49      i386    geteuid                 sys_geteuid16
50      i386    getegid                 sys_getegid16
51      i386    acct                    sys_acct
52      i386    umount2                 sys_umount
53      i386    lock
54      i386    ioctl                   sys_ioctl                       compat_sys_ioctl
55      i386    fcntl                   sys_fcntl                       compat_sys_fcntl64
56      i386    mpx
57      i386    setpgid                 sys_setpgid
58      i386    ulimit
59      i386    oldolduname             sys_olduname
60      i386    umask                   sys_umask
61      i386    chroot                  sys_chroot
62      i386    ustat                   sys_ustat                       compat_sys_ustat
63      i386    dup2                    sys_dup2
64      i386    getppid                 sys_getppid
65      i386    getpgrp                 sys_getpgrp
66      i386    setsid                  sys_setsid
67      i386    sigaction               sys_sigaction                   compat_sys_sigaction
68      i386    sgetmask                sys_sgetmask
69      i386    ssetmask                sys_ssetmask
70      i386    setreuid                sys_setreuid16
71      i386    setregid                sys_setregid16
72      i386    sigsuspend              sys_sigsuspend
73      i386    sigpending              sys_sigpending                  compat_sys_sigpending
74      i386    sethostname             sys_sethostname
75      i386    setrlimit               sys_setrlimit                   compat_sys_setrlimit
76      i386    getrlimit               sys_old_getrlimit               compat_sys_old_getrlimit
77      i386    getrusage               sys_getrusage                   compat_sys_getrusage
78      i386    gettimeofday            sys_gettimeofday                compat_sys_gettimeofday
79      i386    settimeofday            sys_settimeofday                compat_sys_settimeofday
80      i386    getgroups               sys_getgroups16
81      i386    setgroups               sys_setgroups16
82      i386    select                  sys_old_select                  compat_sys_old_select
83      i386    symlink                 sys_symlink
84      i386    oldlstat                sys_lstat
85      i386    readlink                sys_readlink
86      i386    uselib                  sys_uselib
87      i386    swapon                  sys_swapon
88      i386    reboot                  sys_reboot
89      i386    readdir                 sys_old_readdir                 compat_sys_old_readdir
90      i386    mmap                    sys_old_mmap                    compat_sys_ia32_mmap
91      i386    munmap                  sys_munmap
92      i386    truncate                sys_truncate                    compat_sys_truncate
93      i386    ftruncate               sys_ftruncate                   compat_sys_ftruncate
94      i386    fchmod                  sys_fchmod
95      i386    fchown                  sys_fchown16
96      i386    getpriority             sys_getpriority
97      i386    setpriority             sys_setpriority
98      i386    profil
99      i386    statfs                  sys_statfs                      compat_sys_statfs
100     i386    fstatfs                 sys_fstatfs                     compat_sys_fstatfs
101     i386    ioperm                  sys_ioperm
102     i386    socketcall              sys_socketcall                  compat_sys_socketcall
103     i386    syslog                  sys_syslog
104     i386    setitimer               sys_setitimer                   compat_sys_setitimer
105     i386    getitimer               sys_getitimer                   compat_sys_getitimer
106     i386    stat                    sys_newstat                     compat_sys_newstat
107     i386    lstat                   sys_newlstat                    compat_sys_newlstat
108     i386    fstat                   sys_newfstat                    compat_sys_newfstat
109     i386    olduname                sys_uname
110     i386    iopl                    sys_iopl
111     i386    vhangup                 sys_vhangup
112     i386    idle
113     i386    vm86old                 sys_vm86old                     sys_ni_syscall
114     i386    wait4                   sys_wait4                       compat_sys_wait4
115     i386    swapoff                 sys_swapoff
116     i386    sysinfo                 sys_sysinfo                     compat_sys_sysinfo
117     i386    ipc                     sys_ipc                         compat_sys_ipc
118     i386    fsync                   sys_fsync
119     i386    sigreturn               sys_sigreturn                   compat_sys_sigreturn
120     i386    clone                   sys_clone                       compat_sys_ia32_clone
121     i386    setdomainname           sys_setdomainname
122     i386    uname                   sys_newuname
123     i386    modify_ldt              sys_modify_ldt
124     i386    adjtimex                sys_adjtimex_time32
125     i386    mprotect                sys_mprotect
126     i386    sigprocmask             sys_sigprocmask                 compat_sys_sigprocmask
127     i386    create_module
128     i386    init_module             sys_init_module
129     i386    delete_module           sys_delete_module
130     i386    get_kernel_syms
131     i386    quotactl                sys_quotactl
132     i386    getpgid                 sys_getpgid
133     i386    fchdir                  sys_fchdir
134     i386    bdflush                 sys_ni_syscall
135     i386    sysfs                   sys_sysfs
136     i386    personality             sys_personality
137     i386    afs_syscall
138     i386    setfsuid                sys_setfsuid16
139     i386    setfsgid                sys_setfsgid16
140     i386    _llseek                 sys_llseek
141     i386    getdents                sys_getdents                    compat_sys_getdents
142     i386    _newselect              sys_select                      compat_sys_select
143     i386    flock                   sys_flock
144     i386    msync                   sys_msync
145     i386    readv                   sys_readv
146     i386    writev                  sys_writev
147     i386    getsid                  sys_getsid
148     i386    fdatasync               sys_fdatasync
149     i386    _sysctl                 sys_ni_syscall
150     i386    mlock                   sys_mlock
151     i386    munlock                 sys_munlock
152     i386    mlockall                sys_mlockall
153     i386    munlockall              sys_munlockall
154     i386    sched_setparam          sys_sched_setparam
155     i386    sched_getparam          sys_sched_getparam
156     i386    sched_setscheduler      sys_sched_setscheduler
157     i386    sched_getscheduler      sys_sched_getscheduler
158     i386    sched_yield             sys_sched_yield
159     i386    sched_get_priority_max  sys_sched_get_priority_max
160     i386    sched_get_priority_min  sys_sched_get_priority_min
161     i386    sched_rr_get_interval   sys_sched_rr_get_interval_time32
162     i386    nanosleep               sys_nanosleep_time32
163     i386    mremap                  sys_mremap
164     i386    setresuid               sys_setresuid16
165     i386    getresuid               sys_getresuid16
166     i386    vm86                    sys_vm86                        sys_ni_syscall
167     i386    query_module
168     i386    poll                    sys_poll
169     i386    nfsservctl
170     i386    setresgid               sys_setresgid16
171     i386    getresgid               sys_getresgid16
172     i386    prctl                   sys_prctl
173     i386    rt_sigreturn            sys_rt_sigreturn                compat_sys_rt_sigreturn
174     i386    rt_sigaction            sys_rt_sigaction                compat_sys_rt_sigaction
175     i386    rt_sigprocmask          sys_rt_sigprocmask              compat_sys_rt_sigprocmask
176     i386    rt_sigpending           sys_rt_sigpending               compat_sys_rt_sigpending
177     i386    rt_sigtimedwait         sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
178     i386    rt_sigqueueinfo         sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
179     i386    rt_sigsuspend           sys_rt_sigsuspend               compat_sys_rt_sigsuspend
180     i386    pread64                 sys_ia32_pread64
181     i386    pwrite64                sys_ia32_pwrite64
182     i386    chown                   sys_chown16
183     i386    getcwd                  sys_getcwd
184     i386    capget                  sys_capget
185     i386    capset                  sys_capset
186     i386    sigaltstack             sys_sigaltstack                 compat_sys_sigaltstack
187     i386    sendfile                sys_sendfile                    compat_sys_sendfile
188     i386    getpmsg
189     i386    putpmsg
190     i386    vfork                   sys_vfork
191     i386    ugetrlimit              sys_getrlimit                   compat_sys_getrlimit
192     i386    mmap2                   sys_mmap_pgoff
193     i386    truncate64              sys_ia32_truncate64
194     i386    ftruncate64             sys_ia32_ftruncate64
195     i386    stat64                  sys_stat64                      compat_sys_ia32_stat64
196     i386    lstat64                 sys_lstat64                     compat_sys_ia32_lstat64
197     i386    fstat64                 sys_fstat64                     compat_sys_ia32_fstat64
198     i386    lchown32                sys_lchown
199     i386    getuid32                sys_getuid
200     i386    getgid32                sys_getgid
201     i386    geteuid32               sys_geteuid
202     i386    getegid32               sys_getegid
203     i386    setreuid32              sys_setreuid
204     i386    setregid32              sys_setregid
205     i386    getgroups32             sys_getgroups
206     i386    setgroups32             sys_setgroups
207     i386    fchown32                sys_fchown
208     i386    setresuid32             sys_setresuid
209     i386    getresuid32             sys_getresuid
210     i386    setresgid32             sys_setresgid
211     i386    getresgid32             sys_getresgid
212     i386    chown32                 sys_chown
213     i386    setuid32                sys_setuid
214     i386    setgid32                sys_setgid
215     i386    setfsuid32              sys_setfsuid
216     i386    setfsgid32              sys_setfsgid
217     i386    pivot_root              sys_pivot_root
218     i386    mincore                 sys_mincore
219     i386    madvise                 sys_madvise
220     i386    getdents64              sys_getdents64
221     i386    fcntl64                 sys_fcntl64                     compat_sys_fcntl64
224     i386    gettid                  sys_gettid
225     i386    readahead               sys_ia32_readahead
226     i386    setxattr                sys_setxattr
227     i386    lsetxattr               sys_lsetxattr
228     i386    fsetxattr               sys_fsetxattr
229     i386    getxattr                sys_getxattr
230     i386    lgetxattr               sys_lgetxattr
231     i386    fgetxattr               sys_fgetxattr
232     i386    listxattr               sys_listxattr
233     i386    llistxattr              sys_llistxattr
234     i386    flistxattr              sys_flistxattr
235     i386    removexattr             sys_removexattr
236     i386    lremovexattr            sys_lremovexattr
237     i386    fremovexattr            sys_fremovexattr
238     i386    tkill                   sys_tkill
239     i386    sendfile64              sys_sendfile64
240     i386    futex                   sys_futex_time32
241     i386    sched_setaffinity       sys_sched_setaffinity           compat_sys_sched_setaffinity
242     i386    sched_getaffinity       sys_sched_getaffinity           compat_sys_sched_getaffinity
243     i386    set_thread_area         sys_set_thread_area
244     i386    get_thread_area         sys_get_thread_area
245     i386    io_setup                sys_io_setup                    compat_sys_io_setup
246     i386    io_destroy              sys_io_destroy
247     i386    io_getevents            sys_io_getevents_time32
248     i386    io_submit               sys_io_submit                   compat_sys_io_submit
249     i386    io_cancel               sys_io_cancel
250     i386    fadvise64               sys_ia32_fadvise64
252     i386    exit_group              sys_exit_group                  -                       noreturn
253     i386    lookup_dcookie
254     i386    epoll_create            sys_epoll_create
255     i386    epoll_ctl               sys_epoll_ctl
256     i386    epoll_wait              sys_epoll_wait
257     i386    remap_file_pages        sys_remap_file_pages
258     i386    set_tid_address         sys_set_tid_address
259     i386    timer_create            sys_timer_create                compat_sys_timer_create
260     i386    timer_settime           sys_timer_settime32
261     i386    timer_gettime           sys_timer_gettime32
262     i386    timer_getoverrun        sys_timer_getoverrun
263     i386    timer_delete            sys_timer_delete
264     i386    clock_settime           sys_clock_settime32
265     i386    clock_gettime           sys_clock_gettime32
266     i386    clock_getres            sys_clock_getres_time32
267     i386    clock_nanosleep         sys_clock_nanosleep_time32
268     i386    statfs64                sys_statfs64                    compat_sys_statfs64
269     i386    fstatfs64               sys_fstatfs64                   compat_sys_fstatfs64
270     i386    tgkill                  sys_tgkill
271     i386    utimes                  sys_utimes_time32
272     i386    fadvise64_64            sys_ia32_fadvise64_64
273     i386    vserver
274     i386    mbind                   sys_mbind
275     i386    get_mempolicy           sys_get_mempolicy
276     i386    set_mempolicy           sys_set_mempolicy
277     i386    mq_open                 sys_mq_open                     compat_sys_mq_open
278     i386    mq_unlink               sys_mq_unlink
279     i386    mq_timedsend            sys_mq_timedsend_time32
280     i386    mq_timedreceive         sys_mq_timedreceive_time32
281     i386    mq_notify               sys_mq_notify                   compat_sys_mq_notify
282     i386    mq_getsetattr           sys_mq_getsetattr               compat_sys_mq_getsetattr
283     i386    kexec_load              sys_kexec_load                  compat_sys_kexec_load
284     i386    waitid                  sys_waitid                      compat_sys_waitid
286     i386    add_key                 sys_add_key
287     i386    request_key             sys_request_key
288     i386    keyctl                  sys_keyctl                      compat_sys_keyctl
289     i386    ioprio_set              sys_ioprio_set
290     i386    ioprio_get              sys_ioprio_get
291     i386    inotify_init            sys_inotify_init
292     i386    inotify_add_watch       sys_inotify_add_watch
293     i386    inotify_rm_watch        sys_inotify_rm_watch
294     i386    migrate_pages           sys_migrate_pages
295     i386    openat                  sys_openat                      compat_sys_openat
296     i386    mkdirat                 sys_mkdirat
297     i386    mknodat                 sys_mknodat
298     i386    fchownat                sys_fchownat
299     i386    futimesat               sys_futimesat_time32
300     i386    fstatat64               sys_fstatat64                   compat_sys_ia32_fstatat64
301     i386    unlinkat                sys_unlinkat
302     i386    renameat                sys_renameat
303     i386    linkat                  sys_linkat
304     i386    symlinkat               sys_symlinkat
305     i386    readlinkat              sys_readlinkat
306     i386    fchmodat                sys_fchmodat
307     i386    faccessat               sys_faccessat
308     i386    pselect6                sys_pselect6_time32             compat_sys_pselect6_time32
309     i386    ppoll                   sys_ppoll_time32                compat_sys_ppoll_time32
310     i386    unshare                 sys_unshare
311     i386    set_robust_list         sys_set_robust_list             compat_sys_set_robust_list
312     i386    get_robust_list         sys_get_robust_list             compat_sys_get_robust_list
313     i386    splice                  sys_splice
314     i386    sync_file_range         sys_ia32_sync_file_range
315     i386    tee                     sys_tee
316     i386    vmsplice                sys_vmsplice
317     i386    move_pages              sys_move_pages
318     i386    getcpu                  sys_getcpu
319     i386    epoll_pwait             sys_epoll_pwait
320     i386    utimensat               sys_utimensat_time32
321     i386    signalfd                sys_signalfd                    compat_sys_signalfd
322     i386    timerfd_create          sys_timerfd_create
323     i386    eventfd                 sys_eventfd
324     i386    fallocate               sys_ia32_fallocate
325     i386    timerfd_settime         sys_timerfd_settime32
326     i386    timerfd_gettime         sys_timerfd_gettime32
327     i386    signalfd4               sys_signalfd4                   compat_sys_signalfd4
328     i386    eventfd2                sys_eventfd2
329     i386    epoll_create1           sys_epoll_create1
330     i386    dup3                    sys_dup3
331     i386    pipe2                   sys_pipe2
332     i386    inotify_init1           sys_inotify_init1
333     i386    preadv                  sys_preadv                      compat_sys_preadv
334     i386    pwritev                 sys_pwritev                     compat_sys_pwritev
335     i386    rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
336     i386    perf_event_open         sys_perf_event_open
337     i386    recvmmsg                sys_recvmmsg_time32             compat_sys_recvmmsg_time32
338     i386    fanotify_init           sys_fanotify_init
339     i386    fanotify_mark           sys_fanotify_mark               compat_sys_fanotify_mark
340     i386    prlimit64               sys_prlimit64
341     i386    name_to_handle_at       sys_name_to_handle_at
342     i386    open_by_handle_at       sys_open_by_handle_at           compat_sys_open_by_handle_at
343     i386    clock_adjtime           sys_clock_adjtime32
344     i386    syncfs                  sys_syncfs
345     i386    sendmmsg                sys_sendmmsg                    compat_sys_sendmmsg
346     i386    setns                   sys_setns
347     i386    process_vm_readv        sys_process_vm_readv
348     i386    process_vm_writev       sys_process_vm_writev
349     i386    kcmp                    sys_kcmp
350     i386    finit_module            sys_finit_module
351     i386    sched_setattr           sys_sched_setattr
352     i386    sched_getattr           sys_sched_getattr
353     i386    renameat2               sys_renameat2
354     i386    seccomp                 sys_seccomp
355     i386    getrandom               sys_getrandom
356     i386    memfd_create            sys_memfd_create
357     i386    bpf                     sys_bpf
358     i386    execveat                sys_execveat                    compat_sys_execveat
359     i386    socket                  sys_socket
360     i386    socketpair              sys_socketpair
361     i386    bind                    sys_bind
362     i386    connect                 sys_connect
363     i386    listen                  sys_listen
364     i386    accept4                 sys_accept4
365     i386    getsockopt              sys_getsockopt                  sys_getsockopt
366     i386    setsockopt              sys_setsockopt                  sys_setsockopt
367     i386    getsockname             sys_getsockname
368     i386    getpeername             sys_getpeername
369     i386    sendto                  sys_sendto
370     i386    sendmsg                 sys_sendmsg                     compat_sys_sendmsg
371     i386    recvfrom                sys_recvfrom                    compat_sys_recvfrom
372     i386    recvmsg                 sys_recvmsg                     compat_sys_recvmsg
373     i386    shutdown                sys_shutdown
374     i386    userfaultfd             sys_userfaultfd
375     i386    membarrier              sys_membarrier
376     i386    mlock2                  sys_mlock2
377     i386    copy_file_range         sys_copy_file_range
378     i386    preadv2                 sys_preadv2                     compat_sys_preadv2
379     i386    pwritev2                sys_pwritev2                    compat_sys_pwritev2
380     i386    pkey_mprotect           sys_pkey_mprotect
381     i386    pkey_alloc              sys_pkey_alloc
382     i386    pkey_free               sys_pkey_free
383     i386    statx                   sys_statx
384     i386    arch_prctl              sys_arch_prctl
385     i386    io_pgetevents           sys_io_pgetevents_time32        compat_sys_io_pgetevents
386     i386    rseq                    sys_rseq
393     i386    semget                  sys_semget
394     i386    semctl                  sys_semctl                      compat_sys_semctl
395     i386    shmget                  sys_shmget
396     i386    shmctl                  sys_shmctl                      compat_sys_shmctl
397     i386    shmat                   sys_shmat                       compat_sys_shmat
398     i386    shmdt                   sys_shmdt
399     i386    msgget                  sys_msgget
400     i386    msgsnd                  sys_msgsnd                      compat_sys_msgsnd
401     i386    msgrcv                  sys_msgrcv                      compat_sys_msgrcv
402     i386    msgctl                  sys_msgctl                      compat_sys_msgctl
403     i386    clock_gettime64         sys_clock_gettime
404     i386    clock_settime64         sys_clock_settime
405     i386    clock_adjtime64         sys_clock_adjtime
406     i386    clock_getres_time64     sys_clock_getres
407     i386    clock_nanosleep_time64  sys_clock_nanosleep
408     i386    timer_gettime64         sys_timer_gettime
409     i386    timer_settime64         sys_timer_settime
410     i386    timerfd_gettime64       sys_timerfd_gettime
411     i386    timerfd_settime64       sys_timerfd_settime
412     i386    utimensat_time64        sys_utimensat
413     i386    pselect6_time64         sys_pselect6                    compat_sys_pselect6_time64
414     i386    ppoll_time64            sys_ppoll                       compat_sys_ppoll_time64
416     i386    io_pgetevents_time64    sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     i386    recvmmsg_time64         sys_recvmmsg                    compat_sys_recvmmsg_time64
418     i386    mq_timedsend_time64     sys_mq_timedsend
419     i386    mq_timedreceive_time64  sys_mq_timedreceive
420     i386    semtimedop_time64       sys_semtimedop
421     i386    rt_sigtimedwait_time64  sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     i386    futex_time64            sys_futex
423     i386    sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     i386    pidfd_send_signal       sys_pidfd_send_signal
425     i386    io_uring_setup          sys_io_uring_setup
426     i386    io_uring_enter          sys_io_uring_enter
427     i386    io_uring_register       sys_io_uring_register
428     i386    open_tree               sys_open_tree
429     i386    move_mount              sys_move_mount
430     i386    fsopen                  sys_fsopen
431     i386    fsconfig                sys_fsconfig
432     i386    fsmount                 sys_fsmount
433     i386    fspick                  sys_fspick
434     i386    pidfd_open              sys_pidfd_open
435     i386    clone3                  sys_clone3
436     i386    close_range             sys_close_range
437     i386    openat2                 sys_openat2
438     i386    pidfd_getfd             sys_pidfd_getfd
439     i386    faccessat2              sys_faccessat2
440     i386    process_madvise         sys_process_madvise
441     i386    epoll_pwait2            sys_epoll_pwait2                compat_sys_epoll_pwait2
442     i386    mount_setattr           sys_mount_setattr
443     i386    quotactl_fd             sys_quotactl_fd
444     i386    landlock_create_ruleset sys_landlock_create_ruleset
445     i386    landlock_add_rule       sys_landlock_add_rule
446     i386    landlock_restrict_self  sys_landlock_restrict_self
447     i386    memfd_secret            sys_memfd_secret
448     i386    process_mrelease        sys_process_mrelease
449     i386    futex_waitv             sys_futex_waitv
450     i386    set_mempolicy_home_node         sys_set_mempolicy_home_node
451     i386    cachestat               sys_cachestat
452     i386    fchmodat2               sys_fchmodat2
453     i386    map_shadow_stack        sys_map_shadow_stack
454     i386    futex_wake              sys_futex_wake
455     i386    futex_wait              sys_futex_wait
456     i386    futex_requeue           sys_futex_requeue
457     i386    statmount               sys_statmount
458     i386    listmount               sys_listmount
459     i386    lsm_get_self_attr       sys_lsm_get_self_attr
460     i386    lsm_set_self_attr       sys_lsm_set_self_attr
461     i386    lsm_list_modules        sys_lsm_list_modules
462     i386    mseal                   sys_mseal
463     i386    setxattrat              sys_setxattrat
464     i386    getxattrat              sys_getxattrat
465     i386    listxattrat             sys_listxattrat
466     i386    removexattrat           sys_removexattrat
467     i386    open_tree_attr          sys_open_tree_attr
468     i386    file_getattr            sys_file_getattr
469     i386    file_setattr            sys_file_setattr
470     i386    listns                  sys_listns
471     i386    rseq_slice_yield        sys_rseq_slice_yield
"""


# ARM64
# - arch/arm64/tools/syscall_64_tbl -> scripts/syscall.tbl
arm64_syscall_tbl = """
0       common  io_setup                        sys_io_setup                    compat_sys_io_setup
1       common  io_destroy                      sys_io_destroy
2       common  io_submit                       sys_io_submit                   compat_sys_io_submit
3       common  io_cancel                       sys_io_cancel
4       time32  io_getevents                    sys_io_getevents_time32
4       64      io_getevents                    sys_io_getevents
5       common  setxattr                        sys_setxattr
6       common  lsetxattr                       sys_lsetxattr
7       common  fsetxattr                       sys_fsetxattr
8       common  getxattr                        sys_getxattr
9       common  lgetxattr                       sys_lgetxattr
10      common  fgetxattr                       sys_fgetxattr
11      common  listxattr                       sys_listxattr
12      common  llistxattr                      sys_llistxattr
13      common  flistxattr                      sys_flistxattr
14      common  removexattr                     sys_removexattr
15      common  lremovexattr                    sys_lremovexattr
16      common  fremovexattr                    sys_fremovexattr
17      common  getcwd                          sys_getcwd
18      common  lookup_dcookie                  sys_ni_syscall
19      common  eventfd2                        sys_eventfd2
20      common  epoll_create1                   sys_epoll_create1
21      common  epoll_ctl                       sys_epoll_ctl
22      common  epoll_pwait                     sys_epoll_pwait                 compat_sys_epoll_pwait
23      common  dup                             sys_dup
24      common  dup3                            sys_dup3
25      32      fcntl64                         sys_fcntl64                     compat_sys_fcntl64
25      64      fcntl                           sys_fcntl
26      common  inotify_init1                   sys_inotify_init1
27      common  inotify_add_watch               sys_inotify_add_watch
28      common  inotify_rm_watch                sys_inotify_rm_watch
29      common  ioctl                           sys_ioctl                       compat_sys_ioctl
30      common  ioprio_set                      sys_ioprio_set
31      common  ioprio_get                      sys_ioprio_get
32      common  flock                           sys_flock
33      common  mknodat                         sys_mknodat
34      common  mkdirat                         sys_mkdirat
35      common  unlinkat                        sys_unlinkat
36      common  symlinkat                       sys_symlinkat
37      common  linkat                          sys_linkat
38      renameat renameat                       sys_renameat
39      common  umount2                         sys_umount
40      common  mount                           sys_mount
41      common  pivot_root                      sys_pivot_root
42      common  nfsservctl                      sys_ni_syscall
43      32      statfs64                        sys_statfs64                    compat_sys_statfs64
43      64      statfs                          sys_statfs
44      32      fstatfs64                       sys_fstatfs64                   compat_sys_fstatfs64
44      64      fstatfs                         sys_fstatfs
45      32      truncate64                      sys_truncate64                  compat_sys_truncate64
45      64      truncate                        sys_truncate
46      32      ftruncate64                     sys_ftruncate64                 compat_sys_ftruncate64
46      64      ftruncate                       sys_ftruncate
47      common  fallocate                       sys_fallocate                   compat_sys_fallocate
48      common  faccessat                       sys_faccessat
49      common  chdir                           sys_chdir
50      common  fchdir                          sys_fchdir
51      common  chroot                          sys_chroot
52      common  fchmod                          sys_fchmod
53      common  fchmodat                        sys_fchmodat
54      common  fchownat                        sys_fchownat
55      common  fchown                          sys_fchown
56      common  openat                          sys_openat
57      common  close                           sys_close
58      common  vhangup                         sys_vhangup
59      common  pipe2                           sys_pipe2
60      common  quotactl                        sys_quotactl
61      common  getdents64                      sys_getdents64
62      32      llseek                          sys_llseek
62      64      lseek                           sys_lseek
63      common  read                            sys_read
64      common  write                           sys_write
65      common  readv                           sys_readv                       sys_readv
66      common  writev                          sys_writev                      sys_writev
67      common  pread64                         sys_pread64                     compat_sys_pread64
68      common  pwrite64                        sys_pwrite64                    compat_sys_pwrite64
69      common  preadv                          sys_preadv                      compat_sys_preadv
70      common  pwritev                         sys_pwritev                     compat_sys_pwritev
71      32      sendfile64                      sys_sendfile64
71      64      sendfile                        sys_sendfile64
72      time32  pselect6                        sys_pselect6_time32             compat_sys_pselect6_time32
72      64      pselect6                        sys_pselect6
73      time32  ppoll                           sys_ppoll_time32                compat_sys_ppoll_time32
73      64      ppoll                           sys_ppoll
74      common  signalfd4                       sys_signalfd4                   compat_sys_signalfd4
75      common  vmsplice                        sys_vmsplice
76      common  splice                          sys_splice
77      common  tee                             sys_tee
78      common  readlinkat                      sys_readlinkat
79      stat64  fstatat64                       sys_fstatat64
79      64      newfstatat                      sys_newfstatat
80      stat64  fstat64                         sys_fstat64
80      64      fstat                           sys_newfstat
81      common  sync                            sys_sync
82      common  fsync                           sys_fsync
83      common  fdatasync                       sys_fdatasync
84      common  sync_file_range                 sys_sync_file_range             compat_sys_sync_file_range
85      common  timerfd_create                  sys_timerfd_create
86      time32  timerfd_settime                 sys_timerfd_settime32
86      64      timerfd_settime                 sys_timerfd_settime
87      time32  timerfd_gettime                 sys_timerfd_gettime32
87      64      timerfd_gettime                 sys_timerfd_gettime
88      time32  utimensat                       sys_utimensat_time32
88      64      utimensat                       sys_utimensat
89      common  acct                            sys_acct
90      common  capget                          sys_capget
91      common  capset                          sys_capset
92      common  personality                     sys_personality
93      common  exit                            sys_exit
94      common  exit_group                      sys_exit_group
95      common  waitid                          sys_waitid                      compat_sys_waitid
96      common  set_tid_address                 sys_set_tid_address
97      common  unshare                         sys_unshare
98      time32  futex                           sys_futex_time32
98      64      futex                           sys_futex
99      common  set_robust_list                 sys_set_robust_list             compat_sys_set_robust_list
100     common  get_robust_list                 sys_get_robust_list             compat_sys_get_robust_list
101     time32  nanosleep                       sys_nanosleep_time32
101     64      nanosleep                       sys_nanosleep
102     common  getitimer                       sys_getitimer                   compat_sys_getitimer
103     common  setitimer                       sys_setitimer                   compat_sys_setitimer
104     common  kexec_load                      sys_kexec_load                  compat_sys_kexec_load
105     common  init_module                     sys_init_module
106     common  delete_module                   sys_delete_module
107     common  timer_create                    sys_timer_create                compat_sys_timer_create
108     time32  timer_gettime                   sys_timer_gettime32
108     64      timer_gettime                   sys_timer_gettime
109     common  timer_getoverrun                sys_timer_getoverrun
110     time32  timer_settime                   sys_timer_settime32
110     64      timer_settime                   sys_timer_settime
111     common  timer_delete                    sys_timer_delete
112     time32  clock_settime                   sys_clock_settime32
112     64      clock_settime                   sys_clock_settime
113     time32  clock_gettime                   sys_clock_gettime32
113     64      clock_gettime                   sys_clock_gettime
114     time32  clock_getres                    sys_clock_getres_time32
114     64      clock_getres                    sys_clock_getres
115     time32  clock_nanosleep                 sys_clock_nanosleep_time32
115     64      clock_nanosleep                 sys_clock_nanosleep
116     common  syslog                          sys_syslog
117     common  ptrace                          sys_ptrace                      compat_sys_ptrace
118     common  sched_setparam                  sys_sched_setparam
119     common  sched_setscheduler              sys_sched_setscheduler
120     common  sched_getscheduler              sys_sched_getscheduler
121     common  sched_getparam                  sys_sched_getparam
122     common  sched_setaffinity               sys_sched_setaffinity           compat_sys_sched_setaffinity
123     common  sched_getaffinity               sys_sched_getaffinity           compat_sys_sched_getaffinity
124     common  sched_yield                     sys_sched_yield
125     common  sched_get_priority_max          sys_sched_get_priority_max
126     common  sched_get_priority_min          sys_sched_get_priority_min
127     time32  sched_rr_get_interval           sys_sched_rr_get_interval_time32
127     64      sched_rr_get_interval           sys_sched_rr_get_interval
128     common  restart_syscall                 sys_restart_syscall
129     common  kill                            sys_kill
130     common  tkill                           sys_tkill
131     common  tgkill                          sys_tgkill
132     common  sigaltstack                     sys_sigaltstack                 compat_sys_sigaltstack
133     common  rt_sigsuspend                   sys_rt_sigsuspend               compat_sys_rt_sigsuspend
134     common  rt_sigaction                    sys_rt_sigaction                compat_sys_rt_sigaction
135     common  rt_sigprocmask                  sys_rt_sigprocmask              compat_sys_rt_sigprocmask
136     common  rt_sigpending                   sys_rt_sigpending               compat_sys_rt_sigpending
137     time32  rt_sigtimedwait                 sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
137     64      rt_sigtimedwait                 sys_rt_sigtimedwait
138     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
139     common  rt_sigreturn                    sys_rt_sigreturn                compat_sys_rt_sigreturn
140     common  setpriority                     sys_setpriority
141     common  getpriority                     sys_getpriority
142     common  reboot                          sys_reboot
143     common  setregid                        sys_setregid
144     common  setgid                          sys_setgid
145     common  setreuid                        sys_setreuid
146     common  setuid                          sys_setuid
147     common  setresuid                       sys_setresuid
148     common  getresuid                       sys_getresuid
149     common  setresgid                       sys_setresgid
150     common  getresgid                       sys_getresgid
151     common  setfsuid                        sys_setfsuid
152     common  setfsgid                        sys_setfsgid
153     common  times                           sys_times                       compat_sys_times
154     common  setpgid                         sys_setpgid
155     common  getpgid                         sys_getpgid
156     common  getsid                          sys_getsid
157     common  setsid                          sys_setsid
158     common  getgroups                       sys_getgroups
159     common  setgroups                       sys_setgroups
160     common  uname                           sys_newuname
161     common  sethostname                     sys_sethostname
162     common  setdomainname                   sys_setdomainname
163     rlimit  getrlimit                       sys_getrlimit                   compat_sys_getrlimit
164     rlimit  setrlimit                       sys_setrlimit                   compat_sys_setrlimit
165     common  getrusage                       sys_getrusage                   compat_sys_getrusage
166     common  umask                           sys_umask
167     common  prctl                           sys_prctl
168     common  getcpu                          sys_getcpu
169     time32  gettimeofday                    sys_gettimeofday                compat_sys_gettimeofday
169     64      gettimeofday                    sys_gettimeofday
170     time32  settimeofday                    sys_settimeofday                compat_sys_settimeofday
170     64      settimeofday                    sys_settimeofday
171     time32  adjtimex                        sys_adjtimex_time32
171     64      adjtimex                        sys_adjtimex
172     common  getpid                          sys_getpid
173     common  getppid                         sys_getppid
174     common  getuid                          sys_getuid
175     common  geteuid                         sys_geteuid
176     common  getgid                          sys_getgid
177     common  getegid                         sys_getegid
178     common  gettid                          sys_gettid
179     common  sysinfo                         sys_sysinfo                     compat_sys_sysinfo
180     common  mq_open                         sys_mq_open                     compat_sys_mq_open
181     common  mq_unlink                       sys_mq_unlink
182     time32  mq_timedsend                    sys_mq_timedsend_time32
182     64      mq_timedsend                    sys_mq_timedsend
183     time32  mq_timedreceive                 sys_mq_timedreceive_time32
183     64      mq_timedreceive                 sys_mq_timedreceive
184     common  mq_notify                       sys_mq_notify                   compat_sys_mq_notify
185     common  mq_getsetattr                   sys_mq_getsetattr               compat_sys_mq_getsetattr
186     common  msgget                          sys_msgget
187     common  msgctl                          sys_msgctl                      compat_sys_msgctl
188     common  msgrcv                          sys_msgrcv                      compat_sys_msgrcv
189     common  msgsnd                          sys_msgsnd                      compat_sys_msgsnd
190     common  semget                          sys_semget
191     common  semctl                          sys_semctl                      compat_sys_semctl
192     time32  semtimedop                      sys_semtimedop_time32
192     64      semtimedop                      sys_semtimedop
193     common  semop                           sys_semop
194     common  shmget                          sys_shmget
195     common  shmctl                          sys_shmctl                      compat_sys_shmctl
196     common  shmat                           sys_shmat                       compat_sys_shmat
197     common  shmdt                           sys_shmdt
198     common  socket                          sys_socket
199     common  socketpair                      sys_socketpair
200     common  bind                            sys_bind
201     common  listen                          sys_listen
202     common  accept                          sys_accept
203     common  connect                         sys_connect
204     common  getsockname                     sys_getsockname
205     common  getpeername                     sys_getpeername
206     common  sendto                          sys_sendto
207     common  recvfrom                        sys_recvfrom                    compat_sys_recvfrom
208     common  setsockopt                      sys_setsockopt                  sys_setsockopt
209     common  getsockopt                      sys_getsockopt                  sys_getsockopt
210     common  shutdown                        sys_shutdown
211     common  sendmsg                         sys_sendmsg                     compat_sys_sendmsg
212     common  recvmsg                         sys_recvmsg                     compat_sys_recvmsg
213     common  readahead                       sys_readahead                   compat_sys_readahead
214     common  brk                             sys_brk
215     common  munmap                          sys_munmap
216     common  mremap                          sys_mremap
217     common  add_key                         sys_add_key
218     common  request_key                     sys_request_key
219     common  keyctl                          sys_keyctl                      compat_sys_keyctl
220     common  clone                           sys_clone
221     common  execve                          sys_execve                      compat_sys_execve
222     32      mmap2                           sys_mmap2
222     64      mmap                            sys_mmap
223     32      fadvise64_64                    sys_fadvise64_64                compat_sys_fadvise64_64
223     64      fadvise64                       sys_fadvise64_64
224     common  swapon                          sys_swapon
225     common  swapoff                         sys_swapoff
226     common  mprotect                        sys_mprotect
227     common  msync                           sys_msync
228     common  mlock                           sys_mlock
229     common  munlock                         sys_munlock
230     common  mlockall                        sys_mlockall
231     common  munlockall                      sys_munlockall
232     common  mincore                         sys_mincore
233     common  madvise                         sys_madvise
234     common  remap_file_pages                sys_remap_file_pages
235     common  mbind                           sys_mbind
236     common  get_mempolicy                   sys_get_mempolicy
237     common  set_mempolicy                   sys_set_mempolicy
238     common  migrate_pages                   sys_migrate_pages
239     common  move_pages                      sys_move_pages
240     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
241     common  perf_event_open                 sys_perf_event_open
242     common  accept4                         sys_accept4
243     time32  recvmmsg                        sys_recvmmsg_time32             compat_sys_recvmmsg_time32
243     64      recvmmsg                        sys_recvmmsg
244     arc     cacheflush                      sys_cacheflush
245     arc     arc_settls                      sys_arc_settls
246     arc     arc_gettls                      sys_arc_gettls
247     arc     sysfs                           sys_sysfs
248     arc     arc_usr_cmpxchg                 sys_arc_usr_cmpxchg
244     csky    set_thread_area                 sys_set_thread_area
245     csky    cacheflush                      sys_cacheflush
244     nios2   cacheflush                      sys_cacheflush
244     or1k    or1k_atomic                     sys_or1k_atomic
258     riscv   riscv_hwprobe                   sys_riscv_hwprobe
259     riscv   riscv_flush_icache              sys_riscv_flush_icache
260     time32  wait4                           sys_wait4                       compat_sys_wait4
260     64      wait4                           sys_wait4
261     common  prlimit64                       sys_prlimit64
262     common  fanotify_init                   sys_fanotify_init
263     common  fanotify_mark                   sys_fanotify_mark
264     common  name_to_handle_at               sys_name_to_handle_at
265     common  open_by_handle_at               sys_open_by_handle_at
266     time32  clock_adjtime                   sys_clock_adjtime32
266     64      clock_adjtime                   sys_clock_adjtime
267     common  syncfs                          sys_syncfs
268     common  setns                           sys_setns
269     common  sendmmsg                        sys_sendmmsg                    compat_sys_sendmmsg
270     common  process_vm_readv                sys_process_vm_readv
271     common  process_vm_writev               sys_process_vm_writev
272     common  kcmp                            sys_kcmp
273     common  finit_module                    sys_finit_module
274     common  sched_setattr                   sys_sched_setattr
275     common  sched_getattr                   sys_sched_getattr
276     common  renameat2                       sys_renameat2
277     common  seccomp                         sys_seccomp
278     common  getrandom                       sys_getrandom
279     common  memfd_create                    sys_memfd_create
280     common  bpf                             sys_bpf
281     common  execveat                        sys_execveat                    compat_sys_execveat
282     common  userfaultfd                     sys_userfaultfd
283     common  membarrier                      sys_membarrier
284     common  mlock2                          sys_mlock2
285     common  copy_file_range                 sys_copy_file_range
286     common  preadv2                         sys_preadv2                     compat_sys_preadv2
287     common  pwritev2                        sys_pwritev2                    compat_sys_pwritev2
288     common  pkey_mprotect                   sys_pkey_mprotect
289     common  pkey_alloc                      sys_pkey_alloc
290     common  pkey_free                       sys_pkey_free
291     common  statx                           sys_statx
292     time32  io_pgetevents                   sys_io_pgetevents_time32        compat_sys_io_pgetevents
292     64      io_pgetevents                   sys_io_pgetevents
293     common  rseq                            sys_rseq
294     common  kexec_file_load                 sys_kexec_file_load
403     32      clock_gettime64                 sys_clock_gettime
404     32      clock_settime64                 sys_clock_settime
405     32      clock_adjtime64                 sys_clock_adjtime
406     32      clock_getres_time64             sys_clock_getres
407     32      clock_nanosleep_time64          sys_clock_nanosleep
408     32      timer_gettime64                 sys_timer_gettime
409     32      timer_settime64                 sys_timer_settime
410     32      timerfd_gettime64               sys_timerfd_gettime
411     32      timerfd_settime64               sys_timerfd_settime
412     32      utimensat_time64                sys_utimensat
413     32      pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     32      ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     32      io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     32      recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     32      mq_timedsend_time64             sys_mq_timedsend
419     32      mq_timedreceive_time64          sys_mq_timedreceive
420     32      semtimedop_time64               sys_semtimedop
421     32      rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     32      futex_time64                    sys_futex
423     32      sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
447     memfd_secret    memfd_secret            sys_memfd_secret
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# ARM (compat(emulated))
# - arch/arm64/tools/syscall_32.tbl
arm_compat_syscall_tbl = """
0       common  restart_syscall         sys_restart_syscall
1       common  exit                    sys_exit
2       common  fork                    sys_fork
3       common  read                    sys_read
4       common  write                   sys_write
5       common  open                    sys_open                compat_sys_open
6       common  close                   sys_close
8       common  creat                   sys_creat
9       common  link                    sys_link
10      common  unlink                  sys_unlink
11      common  execve                  sys_execve              compat_sys_execve
12      common  chdir                   sys_chdir
14      common  mknod                   sys_mknod
15      common  chmod                   sys_chmod
16      common  lchown                  sys_lchown16
19      common  lseek                   sys_lseek               compat_sys_lseek
20      common  getpid                  sys_getpid
21      common  mount                   sys_mount
23      common  setuid                  sys_setuid16
24      common  getuid                  sys_getuid16
26      common  ptrace                  sys_ptrace              compat_sys_ptrace
29      common  pause                   sys_pause
33      common  access                  sys_access
34      common  nice                    sys_nice
36      common  sync                    sys_sync
37      common  kill                    sys_kill
38      common  rename                  sys_rename
39      common  mkdir                   sys_mkdir
40      common  rmdir                   sys_rmdir
41      common  dup                     sys_dup
42      common  pipe                    sys_pipe
43      common  times                   sys_times               compat_sys_times
45      common  brk                     sys_brk
46      common  setgid                  sys_setgid16
47      common  getgid                  sys_getgid16
49      common  geteuid                 sys_geteuid16
50      common  getegid                 sys_getegid16
51      common  acct                    sys_acct
52      common  umount2                 sys_umount
54      common  ioctl                   sys_ioctl               compat_sys_ioctl
55      common  fcntl                   sys_fcntl               compat_sys_fcntl
57      common  setpgid                 sys_setpgid
60      common  umask                   sys_umask
61      common  chroot                  sys_chroot
62      common  ustat                   sys_ustat               compat_sys_ustat
63      common  dup2                    sys_dup2
64      common  getppid                 sys_getppid
65      common  getpgrp                 sys_getpgrp
66      common  setsid                  sys_setsid
67      common  sigaction               sys_sigaction           compat_sys_sigaction
70      common  setreuid                sys_setreuid16
71      common  setregid                sys_setregid16
72      common  sigsuspend              sys_sigsuspend
73      common  sigpending              sys_sigpending          compat_sys_sigpending
74      common  sethostname             sys_sethostname
75      common  setrlimit               sys_setrlimit           compat_sys_setrlimit
77      common  getrusage               sys_getrusage           compat_sys_getrusage
78      common  gettimeofday            sys_gettimeofday        compat_sys_gettimeofday
79      common  settimeofday            sys_settimeofday        compat_sys_settimeofday
80      common  getgroups               sys_getgroups16
81      common  setgroups               sys_setgroups16
83      common  symlink                 sys_symlink
85      common  readlink                sys_readlink
86      common  uselib                  sys_uselib
87      common  swapon                  sys_swapon
88      common  reboot                  sys_reboot
91      common  munmap                  sys_munmap
92      common  truncate                sys_truncate            compat_sys_truncate
93      common  ftruncate               sys_ftruncate           compat_sys_ftruncate
94      common  fchmod                  sys_fchmod
95      common  fchown                  sys_fchown16
96      common  getpriority             sys_getpriority
97      common  setpriority             sys_setpriority
99      common  statfs                  sys_statfs              compat_sys_statfs
100     common  fstatfs                 sys_fstatfs             compat_sys_fstatfs
103     common  syslog                  sys_syslog
104     common  setitimer               sys_setitimer           compat_sys_setitimer
105     common  getitimer               sys_getitimer           compat_sys_getitimer
106     common  stat                    sys_newstat             compat_sys_newstat
107     common  lstat                   sys_newlstat            compat_sys_newlstat
108     common  fstat                   sys_newfstat            compat_sys_newfstat
111     common  vhangup                 sys_vhangup
114     common  wait4                   sys_wait4               compat_sys_wait4
115     common  swapoff                 sys_swapoff
116     common  sysinfo                 sys_sysinfo             compat_sys_sysinfo
118     common  fsync                   sys_fsync
119     common  sigreturn               sys_sigreturn_wrapper   compat_sys_sigreturn
120     common  clone                   sys_clone
121     common  setdomainname           sys_setdomainname
122     common  uname                   sys_newuname
124     common  adjtimex                sys_adjtimex_time32
125     common  mprotect                sys_mprotect
126     common  sigprocmask             sys_sigprocmask         compat_sys_sigprocmask
128     common  init_module             sys_init_module
129     common  delete_module           sys_delete_module
131     common  quotactl                sys_quotactl
132     common  getpgid                 sys_getpgid
133     common  fchdir                  sys_fchdir
134     common  bdflush                 sys_ni_syscall
135     common  sysfs                   sys_sysfs
136     common  personality             sys_personality
138     common  setfsuid                sys_setfsuid16
139     common  setfsgid                sys_setfsgid16
140     common  _llseek                 sys_llseek
141     common  getdents                sys_getdents            compat_sys_getdents
142     common  _newselect              sys_select              compat_sys_select
143     common  flock                   sys_flock
144     common  msync                   sys_msync
145     common  readv                   sys_readv
146     common  writev                  sys_writev
147     common  getsid                  sys_getsid
148     common  fdatasync               sys_fdatasync
149     common  _sysctl                 sys_ni_syscall
150     common  mlock                   sys_mlock
151     common  munlock                 sys_munlock
152     common  mlockall                sys_mlockall
153     common  munlockall              sys_munlockall
154     common  sched_setparam          sys_sched_setparam
155     common  sched_getparam          sys_sched_getparam
156     common  sched_setscheduler      sys_sched_setscheduler
157     common  sched_getscheduler      sys_sched_getscheduler
158     common  sched_yield             sys_sched_yield
159     common  sched_get_priority_max  sys_sched_get_priority_max
160     common  sched_get_priority_min  sys_sched_get_priority_min
161     common  sched_rr_get_interval   sys_sched_rr_get_interval_time32
162     common  nanosleep               sys_nanosleep_time32
163     common  mremap                  sys_mremap
164     common  setresuid               sys_setresuid16
165     common  getresuid               sys_getresuid16
168     common  poll                    sys_poll
169     common  nfsservctl              sys_ni_syscall
170     common  setresgid               sys_setresgid16
171     common  getresgid               sys_getresgid16
172     common  prctl                   sys_prctl
173     common  rt_sigreturn            sys_rt_sigreturn_wrapper        compat_sys_rt_sigreturn
174     common  rt_sigaction            sys_rt_sigaction        compat_sys_rt_sigaction
175     common  rt_sigprocmask          sys_rt_sigprocmask      compat_sys_rt_sigprocmask
176     common  rt_sigpending           sys_rt_sigpending       compat_sys_rt_sigpending
177     common  rt_sigtimedwait         sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
178     common  rt_sigqueueinfo         sys_rt_sigqueueinfo     compat_sys_rt_sigqueueinfo
179     common  rt_sigsuspend           sys_rt_sigsuspend       compat_sys_rt_sigsuspend
180     common  pread64                 sys_pread64             compat_sys_aarch32_pread64
181     common  pwrite64                sys_pwrite64            compat_sys_aarch32_pwrite64
182     common  chown                   sys_chown16
183     common  getcwd                  sys_getcwd
184     common  capget                  sys_capget
185     common  capset                  sys_capset
186     common  sigaltstack             sys_sigaltstack         compat_sys_sigaltstack
187     common  sendfile                sys_sendfile            compat_sys_sendfile
190     common  vfork                   sys_vfork
191     common  ugetrlimit              sys_getrlimit           compat_sys_getrlimit
192     common  mmap2                   sys_mmap2               compat_sys_aarch32_mmap2
193     common  truncate64              sys_truncate64          compat_sys_aarch32_truncate64
194     common  ftruncate64             sys_ftruncate64         compat_sys_aarch32_ftruncate64
195     common  stat64                  sys_stat64
196     common  lstat64                 sys_lstat64
197     common  fstat64                 sys_fstat64
198     common  lchown32                sys_lchown
199     common  getuid32                sys_getuid
200     common  getgid32                sys_getgid
201     common  geteuid32               sys_geteuid
202     common  getegid32               sys_getegid
203     common  setreuid32              sys_setreuid
204     common  setregid32              sys_setregid
205     common  getgroups32             sys_getgroups
206     common  setgroups32             sys_setgroups
207     common  fchown32                sys_fchown
208     common  setresuid32             sys_setresuid
209     common  getresuid32             sys_getresuid
210     common  setresgid32             sys_setresgid
211     common  getresgid32             sys_getresgid
212     common  chown32                 sys_chown
213     common  setuid32                sys_setuid
214     common  setgid32                sys_setgid
215     common  setfsuid32              sys_setfsuid
216     common  setfsgid32              sys_setfsgid
217     common  getdents64              sys_getdents64
218     common  pivot_root              sys_pivot_root
219     common  mincore                 sys_mincore
220     common  madvise                 sys_madvise
221     common  fcntl64                 sys_fcntl64             compat_sys_fcntl64
224     common  gettid                  sys_gettid
225     common  readahead               sys_readahead           compat_sys_aarch32_readahead
226     common  setxattr                sys_setxattr
227     common  lsetxattr               sys_lsetxattr
228     common  fsetxattr               sys_fsetxattr
229     common  getxattr                sys_getxattr
230     common  lgetxattr               sys_lgetxattr
231     common  fgetxattr               sys_fgetxattr
232     common  listxattr               sys_listxattr
233     common  llistxattr              sys_llistxattr
234     common  flistxattr              sys_flistxattr
235     common  removexattr             sys_removexattr
236     common  lremovexattr            sys_lremovexattr
237     common  fremovexattr            sys_fremovexattr
238     common  tkill                   sys_tkill
239     common  sendfile64              sys_sendfile64
240     common  futex                   sys_futex_time32
241     common  sched_setaffinity       sys_sched_setaffinity   compat_sys_sched_setaffinity
242     common  sched_getaffinity       sys_sched_getaffinity   compat_sys_sched_getaffinity
243     common  io_setup                sys_io_setup            compat_sys_io_setup
244     common  io_destroy              sys_io_destroy
245     common  io_getevents            sys_io_getevents_time32
246     common  io_submit               sys_io_submit           compat_sys_io_submit
247     common  io_cancel               sys_io_cancel
248     common  exit_group              sys_exit_group
249     common  lookup_dcookie          sys_ni_syscall
250     common  epoll_create            sys_epoll_create
251     common  epoll_ctl               sys_epoll_ctl
252     common  epoll_wait              sys_epoll_wait
253     common  remap_file_pages        sys_remap_file_pages
256     common  set_tid_address         sys_set_tid_address
257     common  timer_create            sys_timer_create        compat_sys_timer_create
258     common  timer_settime           sys_timer_settime32
259     common  timer_gettime           sys_timer_gettime32
260     common  timer_getoverrun        sys_timer_getoverrun
261     common  timer_delete            sys_timer_delete
262     common  clock_settime           sys_clock_settime32
263     common  clock_gettime           sys_clock_gettime32
264     common  clock_getres            sys_clock_getres_time32
265     common  clock_nanosleep         sys_clock_nanosleep_time32
266     common  statfs64                sys_statfs64_wrapper    compat_sys_aarch32_statfs64
267     common  fstatfs64               sys_fstatfs64_wrapper   compat_sys_aarch32_fstatfs64
268     common  tgkill                  sys_tgkill
269     common  utimes                  sys_utimes_time32
270     common  arm_fadvise64_64        sys_arm_fadvise64_64    compat_sys_aarch32_fadvise64_64
271     common  pciconfig_iobase        sys_pciconfig_iobase
272     common  pciconfig_read          sys_pciconfig_read
273     common  pciconfig_write         sys_pciconfig_write
274     common  mq_open                 sys_mq_open             compat_sys_mq_open
275     common  mq_unlink               sys_mq_unlink
276     common  mq_timedsend            sys_mq_timedsend_time32
277     common  mq_timedreceive         sys_mq_timedreceive_time32
278     common  mq_notify               sys_mq_notify           compat_sys_mq_notify
279     common  mq_getsetattr           sys_mq_getsetattr       compat_sys_mq_getsetattr
280     common  waitid                  sys_waitid              compat_sys_waitid
281     common  socket                  sys_socket
282     common  bind                    sys_bind
283     common  connect                 sys_connect
284     common  listen                  sys_listen
285     common  accept                  sys_accept
286     common  getsockname             sys_getsockname
287     common  getpeername             sys_getpeername
288     common  socketpair              sys_socketpair
289     common  send                    sys_send
290     common  sendto                  sys_sendto
291     common  recv                    sys_recv                compat_sys_recv
292     common  recvfrom                sys_recvfrom            compat_sys_recvfrom
293     common  shutdown                sys_shutdown
294     common  setsockopt              sys_setsockopt
295     common  getsockopt              sys_getsockopt
296     common  sendmsg                 sys_sendmsg             compat_sys_sendmsg
297     common  recvmsg                 sys_recvmsg             compat_sys_recvmsg
298     common  semop                   sys_semop
299     common  semget                  sys_semget
300     common  semctl                  sys_old_semctl          compat_sys_old_semctl
301     common  msgsnd                  sys_msgsnd              compat_sys_msgsnd
302     common  msgrcv                  sys_msgrcv              compat_sys_msgrcv
303     common  msgget                  sys_msgget
304     common  msgctl                  sys_old_msgctl          compat_sys_old_msgctl
305     common  shmat                   sys_shmat               compat_sys_shmat
306     common  shmdt                   sys_shmdt
307     common  shmget                  sys_shmget
308     common  shmctl                  sys_old_shmctl          compat_sys_old_shmctl
309     common  add_key                 sys_add_key
310     common  request_key             sys_request_key
311     common  keyctl                  sys_keyctl              compat_sys_keyctl
312     common  semtimedop              sys_semtimedop_time32
313     common  vserver                 sys_ni_syscall
314     common  ioprio_set              sys_ioprio_set
315     common  ioprio_get              sys_ioprio_get
316     common  inotify_init            sys_inotify_init
317     common  inotify_add_watch       sys_inotify_add_watch
318     common  inotify_rm_watch        sys_inotify_rm_watch
319     common  mbind                   sys_mbind
320     common  get_mempolicy           sys_get_mempolicy
321     common  set_mempolicy           sys_set_mempolicy
322     common  openat                  sys_openat              compat_sys_openat
323     common  mkdirat                 sys_mkdirat
324     common  mknodat                 sys_mknodat
325     common  fchownat                sys_fchownat
326     common  futimesat               sys_futimesat_time32
327     common  fstatat64               sys_fstatat64
328     common  unlinkat                sys_unlinkat
329     common  renameat                sys_renameat
330     common  linkat                  sys_linkat
331     common  symlinkat               sys_symlinkat
332     common  readlinkat              sys_readlinkat
333     common  fchmodat                sys_fchmodat
334     common  faccessat               sys_faccessat
335     common  pselect6                sys_pselect6_time32     compat_sys_pselect6_time32
336     common  ppoll                   sys_ppoll_time32        compat_sys_ppoll_time32
337     common  unshare                 sys_unshare
338     common  set_robust_list         sys_set_robust_list     compat_sys_set_robust_list
339     common  get_robust_list         sys_get_robust_list     compat_sys_get_robust_list
340     common  splice                  sys_splice
341     common  arm_sync_file_range     sys_sync_file_range2    compat_sys_aarch32_sync_file_range2
342     common  tee                     sys_tee
343     common  vmsplice                sys_vmsplice
344     common  move_pages              sys_move_pages
345     common  getcpu                  sys_getcpu
346     common  epoll_pwait             sys_epoll_pwait         compat_sys_epoll_pwait
347     common  kexec_load              sys_kexec_load          compat_sys_kexec_load
348     common  utimensat               sys_utimensat_time32
349     common  signalfd                sys_signalfd            compat_sys_signalfd
350     common  timerfd_create          sys_timerfd_create
351     common  eventfd                 sys_eventfd
352     common  fallocate               sys_fallocate           compat_sys_aarch32_fallocate
353     common  timerfd_settime         sys_timerfd_settime32
354     common  timerfd_gettime         sys_timerfd_gettime32
355     common  signalfd4               sys_signalfd4           compat_sys_signalfd4
356     common  eventfd2                sys_eventfd2
357     common  epoll_create1           sys_epoll_create1
358     common  dup3                    sys_dup3
359     common  pipe2                   sys_pipe2
360     common  inotify_init1           sys_inotify_init1
361     common  preadv                  sys_preadv              compat_sys_preadv
362     common  pwritev                 sys_pwritev             compat_sys_pwritev
363     common  rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo   compat_sys_rt_tgsigqueueinfo
364     common  perf_event_open         sys_perf_event_open
365     common  recvmmsg                sys_recvmmsg_time32     compat_sys_recvmmsg_time32
366     common  accept4                 sys_accept4
367     common  fanotify_init           sys_fanotify_init
368     common  fanotify_mark           sys_fanotify_mark       compat_sys_fanotify_mark
369     common  prlimit64               sys_prlimit64
370     common  name_to_handle_at       sys_name_to_handle_at
371     common  open_by_handle_at       sys_open_by_handle_at   compat_sys_open_by_handle_at
372     common  clock_adjtime           sys_clock_adjtime32
373     common  syncfs                  sys_syncfs
374     common  sendmmsg                sys_sendmmsg            compat_sys_sendmmsg
375     common  setns                   sys_setns
376     common  process_vm_readv        sys_process_vm_readv
377     common  process_vm_writev       sys_process_vm_writev
378     common  kcmp                    sys_kcmp
379     common  finit_module            sys_finit_module
380     common  sched_setattr           sys_sched_setattr
381     common  sched_getattr           sys_sched_getattr
382     common  renameat2               sys_renameat2
383     common  seccomp                 sys_seccomp
384     common  getrandom               sys_getrandom
385     common  memfd_create            sys_memfd_create
386     common  bpf                     sys_bpf
387     common  execveat                sys_execveat            compat_sys_execveat
388     common  userfaultfd             sys_userfaultfd
389     common  membarrier              sys_membarrier
390     common  mlock2                  sys_mlock2
391     common  copy_file_range         sys_copy_file_range
392     common  preadv2                 sys_preadv2             compat_sys_preadv2
393     common  pwritev2                sys_pwritev2            compat_sys_pwritev2
394     common  pkey_mprotect           sys_pkey_mprotect
395     common  pkey_alloc              sys_pkey_alloc
396     common  pkey_free               sys_pkey_free
397     common  statx                   sys_statx
398     common  rseq                    sys_rseq
399     common  io_pgetevents           sys_io_pgetevents_time32        compat_sys_io_pgetevents
400     common  migrate_pages           sys_migrate_pages
401     common  kexec_file_load         sys_kexec_file_load
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     common  ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     common  io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     common  recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# ARM (native)
# - arch/arm/tools/syscall.tbl
arm_native_syscall_tbl = """
0       common  restart_syscall         sys_restart_syscall
1       common  exit                    sys_exit
2       common  fork                    sys_fork
3       common  read                    sys_read
4       common  write                   sys_write
5       common  open                    sys_open
6       common  close                   sys_close
8       common  creat                   sys_creat
9       common  link                    sys_link
10      common  unlink                  sys_unlink
11      common  execve                  sys_execve
12      common  chdir                   sys_chdir
13      oabi    time                    sys_time32
14      common  mknod                   sys_mknod
15      common  chmod                   sys_chmod
16      common  lchown                  sys_lchown16
19      common  lseek                   sys_lseek
20      common  getpid                  sys_getpid
21      common  mount                   sys_mount
22      oabi    umount                  sys_oldumount
23      common  setuid                  sys_setuid16
24      common  getuid                  sys_getuid16
25      oabi    stime                   sys_stime32
26      common  ptrace                  sys_ptrace
27      oabi    alarm                   sys_alarm
29      common  pause                   sys_pause
30      oabi    utime                   sys_utime32
33      common  access                  sys_access
34      common  nice                    sys_nice
36      common  sync                    sys_sync
37      common  kill                    sys_kill
38      common  rename                  sys_rename
39      common  mkdir                   sys_mkdir
40      common  rmdir                   sys_rmdir
41      common  dup                     sys_dup
42      common  pipe                    sys_pipe
43      common  times                   sys_times
45      common  brk                     sys_brk
46      common  setgid                  sys_setgid16
47      common  getgid                  sys_getgid16
49      common  geteuid                 sys_geteuid16
50      common  getegid                 sys_getegid16
51      common  acct                    sys_acct
52      common  umount2                 sys_umount
54      common  ioctl                   sys_ioctl
55      common  fcntl                   sys_fcntl
57      common  setpgid                 sys_setpgid
60      common  umask                   sys_umask
61      common  chroot                  sys_chroot
62      common  ustat                   sys_ustat
63      common  dup2                    sys_dup2
64      common  getppid                 sys_getppid
65      common  getpgrp                 sys_getpgrp
66      common  setsid                  sys_setsid
67      common  sigaction               sys_sigaction
70      common  setreuid                sys_setreuid16
71      common  setregid                sys_setregid16
72      common  sigsuspend              sys_sigsuspend
73      common  sigpending              sys_sigpending
74      common  sethostname             sys_sethostname
75      common  setrlimit               sys_setrlimit
76      oabi    getrlimit               sys_old_getrlimit
77      common  getrusage               sys_getrusage
78      common  gettimeofday            sys_gettimeofday
79      common  settimeofday            sys_settimeofday
80      common  getgroups               sys_getgroups16
81      common  setgroups               sys_setgroups16
82      oabi    select                  sys_old_select
83      common  symlink                 sys_symlink
85      common  readlink                sys_readlink
86      common  uselib                  sys_uselib
87      common  swapon                  sys_swapon
88      common  reboot                  sys_reboot
89      oabi    readdir                 sys_old_readdir
90      oabi    mmap                    sys_old_mmap
91      common  munmap                  sys_munmap
92      common  truncate                sys_truncate
93      common  ftruncate               sys_ftruncate
94      common  fchmod                  sys_fchmod
95      common  fchown                  sys_fchown16
96      common  getpriority             sys_getpriority
97      common  setpriority             sys_setpriority
99      common  statfs                  sys_statfs
100     common  fstatfs                 sys_fstatfs
102     oabi    socketcall              sys_socketcall          sys_oabi_socketcall
103     common  syslog                  sys_syslog
104     common  setitimer               sys_setitimer
105     common  getitimer               sys_getitimer
106     common  stat                    sys_newstat
107     common  lstat                   sys_newlstat
108     common  fstat                   sys_newfstat
111     common  vhangup                 sys_vhangup
113     oabi    syscall                 sys_syscall
114     common  wait4                   sys_wait4
115     common  swapoff                 sys_swapoff
116     common  sysinfo                 sys_sysinfo
117     oabi    ipc                     sys_ipc                 sys_oabi_ipc
118     common  fsync                   sys_fsync
119     common  sigreturn               sys_sigreturn_wrapper
120     common  clone                   sys_clone
121     common  setdomainname           sys_setdomainname
122     common  uname                   sys_newuname
124     common  adjtimex                sys_adjtimex_time32
125     common  mprotect                sys_mprotect
126     common  sigprocmask             sys_sigprocmask
128     common  init_module             sys_init_module
129     common  delete_module           sys_delete_module
131     common  quotactl                sys_quotactl
132     common  getpgid                 sys_getpgid
133     common  fchdir                  sys_fchdir
134     common  bdflush                 sys_ni_syscall
135     common  sysfs                   sys_sysfs
136     common  personality             sys_personality
138     common  setfsuid                sys_setfsuid16
139     common  setfsgid                sys_setfsgid16
140     common  _llseek                 sys_llseek
141     common  getdents                sys_getdents
142     common  _newselect              sys_select
143     common  flock                   sys_flock
144     common  msync                   sys_msync
145     common  readv                   sys_readv
146     common  writev                  sys_writev
147     common  getsid                  sys_getsid
148     common  fdatasync               sys_fdatasync
149     common  _sysctl                 sys_ni_syscall
150     common  mlock                   sys_mlock
151     common  munlock                 sys_munlock
152     common  mlockall                sys_mlockall
153     common  munlockall              sys_munlockall
154     common  sched_setparam          sys_sched_setparam
155     common  sched_getparam          sys_sched_getparam
156     common  sched_setscheduler      sys_sched_setscheduler
157     common  sched_getscheduler      sys_sched_getscheduler
158     common  sched_yield             sys_sched_yield
159     common  sched_get_priority_max  sys_sched_get_priority_max
160     common  sched_get_priority_min  sys_sched_get_priority_min
161     common  sched_rr_get_interval   sys_sched_rr_get_interval_time32
162     common  nanosleep               sys_nanosleep_time32
163     common  mremap                  sys_mremap
164     common  setresuid               sys_setresuid16
165     common  getresuid               sys_getresuid16
168     common  poll                    sys_poll
169     common  nfsservctl
170     common  setresgid               sys_setresgid16
171     common  getresgid               sys_getresgid16
172     common  prctl                   sys_prctl
173     common  rt_sigreturn            sys_rt_sigreturn_wrapper
174     common  rt_sigaction            sys_rt_sigaction
175     common  rt_sigprocmask          sys_rt_sigprocmask
176     common  rt_sigpending           sys_rt_sigpending
177     common  rt_sigtimedwait         sys_rt_sigtimedwait_time32
178     common  rt_sigqueueinfo         sys_rt_sigqueueinfo
179     common  rt_sigsuspend           sys_rt_sigsuspend
180     common  pread64                 sys_pread64             sys_oabi_pread64
181     common  pwrite64                sys_pwrite64            sys_oabi_pwrite64
182     common  chown                   sys_chown16
183     common  getcwd                  sys_getcwd
184     common  capget                  sys_capget
185     common  capset                  sys_capset
186     common  sigaltstack             sys_sigaltstack
187     common  sendfile                sys_sendfile
190     common  vfork                   sys_vfork
191     common  ugetrlimit              sys_getrlimit
192     common  mmap2                   sys_mmap2
193     common  truncate64              sys_truncate64          sys_oabi_truncate64
194     common  ftruncate64             sys_ftruncate64         sys_oabi_ftruncate64
195     common  stat64                  sys_stat64              sys_oabi_stat64
196     common  lstat64                 sys_lstat64             sys_oabi_lstat64
197     common  fstat64                 sys_fstat64             sys_oabi_fstat64
198     common  lchown32                sys_lchown
199     common  getuid32                sys_getuid
200     common  getgid32                sys_getgid
201     common  geteuid32               sys_geteuid
202     common  getegid32               sys_getegid
203     common  setreuid32              sys_setreuid
204     common  setregid32              sys_setregid
205     common  getgroups32             sys_getgroups
206     common  setgroups32             sys_setgroups
207     common  fchown32                sys_fchown
208     common  setresuid32             sys_setresuid
209     common  getresuid32             sys_getresuid
210     common  setresgid32             sys_setresgid
211     common  getresgid32             sys_getresgid
212     common  chown32                 sys_chown
213     common  setuid32                sys_setuid
214     common  setgid32                sys_setgid
215     common  setfsuid32              sys_setfsuid
216     common  setfsgid32              sys_setfsgid
217     common  getdents64              sys_getdents64
218     common  pivot_root              sys_pivot_root
219     common  mincore                 sys_mincore
220     common  madvise                 sys_madvise
221     common  fcntl64                 sys_fcntl64             sys_oabi_fcntl64
224     common  gettid                  sys_gettid
225     common  readahead               sys_readahead           sys_oabi_readahead
226     common  setxattr                sys_setxattr
227     common  lsetxattr               sys_lsetxattr
228     common  fsetxattr               sys_fsetxattr
229     common  getxattr                sys_getxattr
230     common  lgetxattr               sys_lgetxattr
231     common  fgetxattr               sys_fgetxattr
232     common  listxattr               sys_listxattr
233     common  llistxattr              sys_llistxattr
234     common  flistxattr              sys_flistxattr
235     common  removexattr             sys_removexattr
236     common  lremovexattr            sys_lremovexattr
237     common  fremovexattr            sys_fremovexattr
238     common  tkill                   sys_tkill
239     common  sendfile64              sys_sendfile64
240     common  futex                   sys_futex_time32
241     common  sched_setaffinity       sys_sched_setaffinity
242     common  sched_getaffinity       sys_sched_getaffinity
243     common  io_setup                sys_io_setup
244     common  io_destroy              sys_io_destroy
245     common  io_getevents            sys_io_getevents_time32
246     common  io_submit               sys_io_submit
247     common  io_cancel               sys_io_cancel
248     common  exit_group              sys_exit_group
249     common  lookup_dcookie          sys_ni_syscall
250     common  epoll_create            sys_epoll_create
251     common  epoll_ctl               sys_epoll_ctl           sys_oabi_epoll_ctl
252     common  epoll_wait              sys_epoll_wait
253     common  remap_file_pages        sys_remap_file_pages
256     common  set_tid_address         sys_set_tid_address
257     common  timer_create            sys_timer_create
258     common  timer_settime           sys_timer_settime32
259     common  timer_gettime           sys_timer_gettime32
260     common  timer_getoverrun        sys_timer_getoverrun
261     common  timer_delete            sys_timer_delete
262     common  clock_settime           sys_clock_settime32
263     common  clock_gettime           sys_clock_gettime32
264     common  clock_getres            sys_clock_getres_time32
265     common  clock_nanosleep         sys_clock_nanosleep_time32
266     common  statfs64                sys_statfs64_wrapper
267     common  fstatfs64               sys_fstatfs64_wrapper
268     common  tgkill                  sys_tgkill
269     common  utimes                  sys_utimes_time32
270     common  arm_fadvise64_64        sys_arm_fadvise64_64
271     common  pciconfig_iobase        sys_pciconfig_iobase
272     common  pciconfig_read          sys_pciconfig_read
273     common  pciconfig_write         sys_pciconfig_write
274     common  mq_open                 sys_mq_open
275     common  mq_unlink               sys_mq_unlink
276     common  mq_timedsend            sys_mq_timedsend_time32
277     common  mq_timedreceive         sys_mq_timedreceive_time32
278     common  mq_notify               sys_mq_notify
279     common  mq_getsetattr           sys_mq_getsetattr
280     common  waitid                  sys_waitid
281     common  socket                  sys_socket
282     common  bind                    sys_bind                sys_oabi_bind
283     common  connect                 sys_connect             sys_oabi_connect
284     common  listen                  sys_listen
285     common  accept                  sys_accept
286     common  getsockname             sys_getsockname
287     common  getpeername             sys_getpeername
288     common  socketpair              sys_socketpair
289     common  send                    sys_send
290     common  sendto                  sys_sendto              sys_oabi_sendto
291     common  recv                    sys_recv
292     common  recvfrom                sys_recvfrom
293     common  shutdown                sys_shutdown
294     common  setsockopt              sys_setsockopt
295     common  getsockopt              sys_getsockopt
296     common  sendmsg                 sys_sendmsg             sys_oabi_sendmsg
297     common  recvmsg                 sys_recvmsg
298     common  semop                   sys_semop               sys_oabi_semop
299     common  semget                  sys_semget
300     common  semctl                  sys_old_semctl
301     common  msgsnd                  sys_msgsnd
302     common  msgrcv                  sys_msgrcv
303     common  msgget                  sys_msgget
304     common  msgctl                  sys_old_msgctl
305     common  shmat                   sys_shmat
306     common  shmdt                   sys_shmdt
307     common  shmget                  sys_shmget
308     common  shmctl                  sys_old_shmctl
309     common  add_key                 sys_add_key
310     common  request_key             sys_request_key
311     common  keyctl                  sys_keyctl
312     common  semtimedop              sys_semtimedop_time32   sys_oabi_semtimedop
313     common  vserver
314     common  ioprio_set              sys_ioprio_set
315     common  ioprio_get              sys_ioprio_get
316     common  inotify_init            sys_inotify_init
317     common  inotify_add_watch       sys_inotify_add_watch
318     common  inotify_rm_watch        sys_inotify_rm_watch
319     common  mbind                   sys_mbind
320     common  get_mempolicy           sys_get_mempolicy
321     common  set_mempolicy           sys_set_mempolicy
322     common  openat                  sys_openat
323     common  mkdirat                 sys_mkdirat
324     common  mknodat                 sys_mknodat
325     common  fchownat                sys_fchownat
326     common  futimesat               sys_futimesat_time32
327     common  fstatat64               sys_fstatat64           sys_oabi_fstatat64
328     common  unlinkat                sys_unlinkat
329     common  renameat                sys_renameat
330     common  linkat                  sys_linkat
331     common  symlinkat               sys_symlinkat
332     common  readlinkat              sys_readlinkat
333     common  fchmodat                sys_fchmodat
334     common  faccessat               sys_faccessat
335     common  pselect6                sys_pselect6_time32
336     common  ppoll                   sys_ppoll_time32
337     common  unshare                 sys_unshare
338     common  set_robust_list         sys_set_robust_list
339     common  get_robust_list         sys_get_robust_list
340     common  splice                  sys_splice
341     common  arm_sync_file_range     sys_sync_file_range2
342     common  tee                     sys_tee
343     common  vmsplice                sys_vmsplice
344     common  move_pages              sys_move_pages
345     common  getcpu                  sys_getcpu
346     common  epoll_pwait             sys_epoll_pwait
347     common  kexec_load              sys_kexec_load
348     common  utimensat               sys_utimensat_time32
349     common  signalfd                sys_signalfd
350     common  timerfd_create          sys_timerfd_create
351     common  eventfd                 sys_eventfd
352     common  fallocate               sys_fallocate
353     common  timerfd_settime         sys_timerfd_settime32
354     common  timerfd_gettime         sys_timerfd_gettime32
355     common  signalfd4               sys_signalfd4
356     common  eventfd2                sys_eventfd2
357     common  epoll_create1           sys_epoll_create1
358     common  dup3                    sys_dup3
359     common  pipe2                   sys_pipe2
360     common  inotify_init1           sys_inotify_init1
361     common  preadv                  sys_preadv
362     common  pwritev                 sys_pwritev
363     common  rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo
364     common  perf_event_open         sys_perf_event_open
365     common  recvmmsg                sys_recvmmsg_time32
366     common  accept4                 sys_accept4
367     common  fanotify_init           sys_fanotify_init
368     common  fanotify_mark           sys_fanotify_mark
369     common  prlimit64               sys_prlimit64
370     common  name_to_handle_at       sys_name_to_handle_at
371     common  open_by_handle_at       sys_open_by_handle_at
372     common  clock_adjtime           sys_clock_adjtime32
373     common  syncfs                  sys_syncfs
374     common  sendmmsg                sys_sendmmsg
375     common  setns                   sys_setns
376     common  process_vm_readv        sys_process_vm_readv
377     common  process_vm_writev       sys_process_vm_writev
378     common  kcmp                    sys_kcmp
379     common  finit_module            sys_finit_module
380     common  sched_setattr           sys_sched_setattr
381     common  sched_getattr           sys_sched_getattr
382     common  renameat2               sys_renameat2
383     common  seccomp                 sys_seccomp
384     common  getrandom               sys_getrandom
385     common  memfd_create            sys_memfd_create
386     common  bpf                     sys_bpf
387     common  execveat                sys_execveat
388     common  userfaultfd             sys_userfaultfd
389     common  membarrier              sys_membarrier
390     common  mlock2                  sys_mlock2
391     common  copy_file_range         sys_copy_file_range
392     common  preadv2                 sys_preadv2
393     common  pwritev2                sys_pwritev2
394     common  pkey_mprotect           sys_pkey_mprotect
395     common  pkey_alloc              sys_pkey_alloc
396     common  pkey_free               sys_pkey_free
397     common  statx                   sys_statx
398     common  rseq                    sys_rseq
399     common  io_pgetevents           sys_io_pgetevents_time32
400     common  migrate_pages           sys_migrate_pages
401     common  kexec_file_load         sys_kexec_file_load
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6
414     common  ppoll_time64                    sys_ppoll
416     common  io_pgetevents_time64            sys_io_pgetevents
417     common  recvmmsg_time64                 sys_recvmmsg
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# MIPS o32 (backward compatible ABI, present in /lib)
# - arch/mips/kernel/syscalls/syscall_o32.tbl
mips_o32_syscall_tbl = """
0       o32     syscall                         sys_syscall                     sys32_syscall
1       o32     exit                            sys_exit
2       o32     fork                            __sys_fork
3       o32     read                            sys_read
4       o32     write                           sys_write
5       o32     open                            sys_open                        compat_sys_open
6       o32     close                           sys_close
7       o32     waitpid                         sys_waitpid
8       o32     creat                           sys_creat
9       o32     link                            sys_link
10      o32     unlink                          sys_unlink
11      o32     execve                          sys_execve                      compat_sys_execve
12      o32     chdir                           sys_chdir
13      o32     time                            sys_time32
14      o32     mknod                           sys_mknod
15      o32     chmod                           sys_chmod
16      o32     lchown                          sys_lchown
17      o32     break                           sys_ni_syscall
18      o32     unused18                        sys_ni_syscall
19      o32     lseek                           sys_lseek                       compat_sys_lseek
20      o32     getpid                          sys_getpid
21      o32     mount                           sys_mount
22      o32     umount                          sys_oldumount
23      o32     setuid                          sys_setuid
24      o32     getuid                          sys_getuid
25      o32     stime                           sys_stime32
26      o32     ptrace                          sys_ptrace                      compat_sys_ptrace
27      o32     alarm                           sys_alarm
28      o32     unused28                        sys_ni_syscall
29      o32     pause                           sys_pause
30      o32     utime                           sys_utime32
31      o32     stty                            sys_ni_syscall
32      o32     gtty                            sys_ni_syscall
33      o32     access                          sys_access
34      o32     nice                            sys_nice
35      o32     ftime                           sys_ni_syscall
36      o32     sync                            sys_sync
37      o32     kill                            sys_kill
38      o32     rename                          sys_rename
39      o32     mkdir                           sys_mkdir
40      o32     rmdir                           sys_rmdir
41      o32     dup                             sys_dup
42      o32     pipe                            sysm_pipe
43      o32     times                           sys_times                       compat_sys_times
44      o32     prof                            sys_ni_syscall
45      o32     brk                             sys_brk
46      o32     setgid                          sys_setgid
47      o32     getgid                          sys_getgid
48      o32     signal                          sys_ni_syscall
49      o32     geteuid                         sys_geteuid
50      o32     getegid                         sys_getegid
51      o32     acct                            sys_acct
52      o32     umount2                         sys_umount
53      o32     lock                            sys_ni_syscall
54      o32     ioctl                           sys_ioctl                       compat_sys_ioctl
55      o32     fcntl                           sys_fcntl                       compat_sys_fcntl
56      o32     mpx                             sys_ni_syscall
57      o32     setpgid                         sys_setpgid
58      o32     ulimit                          sys_ni_syscall
59      o32     unused59                        sys_olduname
60      o32     umask                           sys_umask
61      o32     chroot                          sys_chroot
62      o32     ustat                           sys_ustat                       compat_sys_ustat
63      o32     dup2                            sys_dup2
64      o32     getppid                         sys_getppid
65      o32     getpgrp                         sys_getpgrp
66      o32     setsid                          sys_setsid
67      o32     sigaction                       sys_sigaction                   sys_32_sigaction
68      o32     sgetmask                        sys_sgetmask
69      o32     ssetmask                        sys_ssetmask
70      o32     setreuid                        sys_setreuid
71      o32     setregid                        sys_setregid
72      o32     sigsuspend                      sys_sigsuspend                  sys32_sigsuspend
73      o32     sigpending                      sys_sigpending                  compat_sys_sigpending
74      o32     sethostname                     sys_sethostname
75      o32     setrlimit                       sys_setrlimit                   compat_sys_setrlimit
76      o32     getrlimit                       sys_getrlimit                   compat_sys_getrlimit
77      o32     getrusage                       sys_getrusage                   compat_sys_getrusage
78      o32     gettimeofday                    sys_gettimeofday                compat_sys_gettimeofday
79      o32     settimeofday                    sys_settimeofday                compat_sys_settimeofday
80      o32     getgroups                       sys_getgroups
81      o32     setgroups                       sys_setgroups
82      o32     reserved82                      sys_ni_syscall
83      o32     symlink                         sys_symlink
84      o32     unused84                        sys_ni_syscall
85      o32     readlink                        sys_readlink
86      o32     uselib                          sys_uselib
87      o32     swapon                          sys_swapon
88      o32     reboot                          sys_reboot
89      o32     readdir                         sys_old_readdir                 compat_sys_old_readdir
90      o32     mmap                            sys_mips_mmap
91      o32     munmap                          sys_munmap
92      o32     truncate                        sys_truncate                    compat_sys_truncate
93      o32     ftruncate                       sys_ftruncate                   compat_sys_ftruncate
94      o32     fchmod                          sys_fchmod
95      o32     fchown                          sys_fchown
96      o32     getpriority                     sys_getpriority
97      o32     setpriority                     sys_setpriority
98      o32     profil                          sys_ni_syscall
99      o32     statfs                          sys_statfs                      compat_sys_statfs
100     o32     fstatfs                         sys_fstatfs                     compat_sys_fstatfs
101     o32     ioperm                          sys_ni_syscall
102     o32     socketcall                      sys_socketcall                  compat_sys_socketcall
103     o32     syslog                          sys_syslog
104     o32     setitimer                       sys_setitimer                   compat_sys_setitimer
105     o32     getitimer                       sys_getitimer                   compat_sys_getitimer
106     o32     stat                            sys_newstat                     compat_sys_newstat
107     o32     lstat                           sys_newlstat                    compat_sys_newlstat
108     o32     fstat                           sys_newfstat                    compat_sys_newfstat
109     o32     unused109                       sys_uname
110     o32     iopl                            sys_ni_syscall
111     o32     vhangup                         sys_vhangup
112     o32     idle                            sys_ni_syscall
113     o32     vm86                            sys_ni_syscall
114     o32     wait4                           sys_wait4                       compat_sys_wait4
115     o32     swapoff                         sys_swapoff
116     o32     sysinfo                         sys_sysinfo                     compat_sys_sysinfo
117     o32     ipc                             sys_ipc                         compat_sys_ipc
118     o32     fsync                           sys_fsync
119     o32     sigreturn                       sys_sigreturn                   sys32_sigreturn
120     o32     clone                           __sys_clone
121     o32     setdomainname                   sys_setdomainname
122     o32     uname                           sys_newuname
123     o32     modify_ldt                      sys_ni_syscall
124     o32     adjtimex                        sys_adjtimex_time32
125     o32     mprotect                        sys_mprotect
126     o32     sigprocmask                     sys_sigprocmask                 compat_sys_sigprocmask
127     o32     create_module                   sys_ni_syscall
128     o32     init_module                     sys_init_module
129     o32     delete_module                   sys_delete_module
130     o32     get_kernel_syms                 sys_ni_syscall
131     o32     quotactl                        sys_quotactl
132     o32     getpgid                         sys_getpgid
133     o32     fchdir                          sys_fchdir
134     o32     bdflush                         sys_ni_syscall
135     o32     sysfs                           sys_sysfs
136     o32     personality                     sys_personality                 sys_32_personality
137     o32     afs_syscall                     sys_ni_syscall
138     o32     setfsuid                        sys_setfsuid
139     o32     setfsgid                        sys_setfsgid
140     o32     _llseek                         sys_llseek                      sys_32_llseek
141     o32     getdents                        sys_getdents                    compat_sys_getdents
142     o32     _newselect                      sys_select                      compat_sys_select
143     o32     flock                           sys_flock
144     o32     msync                           sys_msync
145     o32     readv                           sys_readv
146     o32     writev                          sys_writev
147     o32     cacheflush                      sys_cacheflush
148     o32     cachectl                        sys_cachectl
149     o32     sysmips                         __sys_sysmips
150     o32     unused150                       sys_ni_syscall
151     o32     getsid                          sys_getsid
152     o32     fdatasync                       sys_fdatasync
153     o32     _sysctl                         sys_ni_syscall
154     o32     mlock                           sys_mlock
155     o32     munlock                         sys_munlock
156     o32     mlockall                        sys_mlockall
157     o32     munlockall                      sys_munlockall
158     o32     sched_setparam                  sys_sched_setparam
159     o32     sched_getparam                  sys_sched_getparam
160     o32     sched_setscheduler              sys_sched_setscheduler
161     o32     sched_getscheduler              sys_sched_getscheduler
162     o32     sched_yield                     sys_sched_yield
163     o32     sched_get_priority_max          sys_sched_get_priority_max
164     o32     sched_get_priority_min          sys_sched_get_priority_min
165     o32     sched_rr_get_interval           sys_sched_rr_get_interval_time32
166     o32     nanosleep                       sys_nanosleep_time32
167     o32     mremap                          sys_mremap
168     o32     accept                          sys_accept
169     o32     bind                            sys_bind
170     o32     connect                         sys_connect
171     o32     getpeername                     sys_getpeername
172     o32     getsockname                     sys_getsockname
173     o32     getsockopt                      sys_getsockopt                  sys_getsockopt
174     o32     listen                          sys_listen
175     o32     recv                            sys_recv                        compat_sys_recv
176     o32     recvfrom                        sys_recvfrom                    compat_sys_recvfrom
177     o32     recvmsg                         sys_recvmsg                     compat_sys_recvmsg
178     o32     send                            sys_send
179     o32     sendmsg                         sys_sendmsg                     compat_sys_sendmsg
180     o32     sendto                          sys_sendto
181     o32     setsockopt                      sys_setsockopt                  sys_setsockopt
182     o32     shutdown                        sys_shutdown
183     o32     socket                          sys_socket
184     o32     socketpair                      sys_socketpair
185     o32     setresuid                       sys_setresuid
186     o32     getresuid                       sys_getresuid
187     o32     query_module                    sys_ni_syscall
188     o32     poll                            sys_poll
189     o32     nfsservctl                      sys_ni_syscall
190     o32     setresgid                       sys_setresgid
191     o32     getresgid                       sys_getresgid
192     o32     prctl                           sys_prctl
193     o32     rt_sigreturn                    sys_rt_sigreturn                sys32_rt_sigreturn
194     o32     rt_sigaction                    sys_rt_sigaction                compat_sys_rt_sigaction
195     o32     rt_sigprocmask                  sys_rt_sigprocmask              compat_sys_rt_sigprocmask
196     o32     rt_sigpending                   sys_rt_sigpending               compat_sys_rt_sigpending
197     o32     rt_sigtimedwait                 sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
198     o32     rt_sigqueueinfo                 sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
199     o32     rt_sigsuspend                   sys_rt_sigsuspend               compat_sys_rt_sigsuspend
200     o32     pread64                         sys_pread64                     sys_32_pread
201     o32     pwrite64                        sys_pwrite64                    sys_32_pwrite
202     o32     chown                           sys_chown
203     o32     getcwd                          sys_getcwd
204     o32     capget                          sys_capget
205     o32     capset                          sys_capset
206     o32     sigaltstack                     sys_sigaltstack                 compat_sys_sigaltstack
207     o32     sendfile                        sys_sendfile                    compat_sys_sendfile
208     o32     getpmsg                         sys_ni_syscall
209     o32     putpmsg                         sys_ni_syscall
210     o32     mmap2                           sys_mips_mmap2
211     o32     truncate64                      sys_truncate64                  sys_32_truncate64
212     o32     ftruncate64                     sys_ftruncate64                 sys_32_ftruncate64
213     o32     stat64                          sys_stat64                      sys_newstat
214     o32     lstat64                         sys_lstat64                     sys_newlstat
215     o32     fstat64                         sys_fstat64                     sys_newfstat
216     o32     pivot_root                      sys_pivot_root
217     o32     mincore                         sys_mincore
218     o32     madvise                         sys_madvise
219     o32     getdents64                      sys_getdents64
220     o32     fcntl64                         sys_fcntl64                     compat_sys_fcntl64
221     o32     reserved221                     sys_ni_syscall
222     o32     gettid                          sys_gettid
223     o32     readahead                       sys_readahead                   sys32_readahead
224     o32     setxattr                        sys_setxattr
225     o32     lsetxattr                       sys_lsetxattr
226     o32     fsetxattr                       sys_fsetxattr
227     o32     getxattr                        sys_getxattr
228     o32     lgetxattr                       sys_lgetxattr
229     o32     fgetxattr                       sys_fgetxattr
230     o32     listxattr                       sys_listxattr
231     o32     llistxattr                      sys_llistxattr
232     o32     flistxattr                      sys_flistxattr
233     o32     removexattr                     sys_removexattr
234     o32     lremovexattr                    sys_lremovexattr
235     o32     fremovexattr                    sys_fremovexattr
236     o32     tkill                           sys_tkill
237     o32     sendfile64                      sys_sendfile64
238     o32     futex                           sys_futex_time32
239     o32     sched_setaffinity               sys_sched_setaffinity           compat_sys_sched_setaffinity
240     o32     sched_getaffinity               sys_sched_getaffinity           compat_sys_sched_getaffinity
241     o32     io_setup                        sys_io_setup                    compat_sys_io_setup
242     o32     io_destroy                      sys_io_destroy
243     o32     io_getevents                    sys_io_getevents_time32
244     o32     io_submit                       sys_io_submit                   compat_sys_io_submit
245     o32     io_cancel                       sys_io_cancel
246     o32     exit_group                      sys_exit_group
247     o32     lookup_dcookie                  sys_ni_syscall
248     o32     epoll_create                    sys_epoll_create
249     o32     epoll_ctl                       sys_epoll_ctl
250     o32     epoll_wait                      sys_epoll_wait
251     o32     remap_file_pages                sys_remap_file_pages
252     o32     set_tid_address                 sys_set_tid_address
253     o32     restart_syscall                 sys_restart_syscall
254     o32     fadvise64                       sys_fadvise64_64                sys32_fadvise64_64
255     o32     statfs64                        sys_statfs64                    compat_sys_statfs64
256     o32     fstatfs64                       sys_fstatfs64                   compat_sys_fstatfs64
257     o32     timer_create                    sys_timer_create                compat_sys_timer_create
258     o32     timer_settime                   sys_timer_settime32
259     o32     timer_gettime                   sys_timer_gettime32
260     o32     timer_getoverrun                sys_timer_getoverrun
261     o32     timer_delete                    sys_timer_delete
262     o32     clock_settime                   sys_clock_settime32
263     o32     clock_gettime                   sys_clock_gettime32
264     o32     clock_getres                    sys_clock_getres_time32
265     o32     clock_nanosleep                 sys_clock_nanosleep_time32
266     o32     tgkill                          sys_tgkill
267     o32     utimes                          sys_utimes_time32
268     o32     mbind                           sys_mbind
269     o32     get_mempolicy                   sys_get_mempolicy
270     o32     set_mempolicy                   sys_set_mempolicy
271     o32     mq_open                         sys_mq_open                     compat_sys_mq_open
272     o32     mq_unlink                       sys_mq_unlink
273     o32     mq_timedsend                    sys_mq_timedsend_time32
274     o32     mq_timedreceive                 sys_mq_timedreceive_time32
275     o32     mq_notify                       sys_mq_notify                   compat_sys_mq_notify
276     o32     mq_getsetattr                   sys_mq_getsetattr               compat_sys_mq_getsetattr
277     o32     vserver                         sys_ni_syscall
278     o32     waitid                          sys_waitid                      compat_sys_waitid
280     o32     add_key                         sys_add_key
281     o32     request_key                     sys_request_key
282     o32     keyctl                          sys_keyctl                      compat_sys_keyctl
283     o32     set_thread_area                 sys_set_thread_area
284     o32     inotify_init                    sys_inotify_init
285     o32     inotify_add_watch               sys_inotify_add_watch
286     o32     inotify_rm_watch                sys_inotify_rm_watch
287     o32     migrate_pages                   sys_migrate_pages
288     o32     openat                          sys_openat                      compat_sys_openat
289     o32     mkdirat                         sys_mkdirat
290     o32     mknodat                         sys_mknodat
291     o32     fchownat                        sys_fchownat
292     o32     futimesat                       sys_futimesat_time32
293     o32     fstatat64                       sys_fstatat64                   sys_newfstatat
294     o32     unlinkat                        sys_unlinkat
295     o32     renameat                        sys_renameat
296     o32     linkat                          sys_linkat
297     o32     symlinkat                       sys_symlinkat
298     o32     readlinkat                      sys_readlinkat
299     o32     fchmodat                        sys_fchmodat
300     o32     faccessat                       sys_faccessat
301     o32     pselect6                        sys_pselect6_time32             compat_sys_pselect6_time32
302     o32     ppoll                           sys_ppoll_time32                compat_sys_ppoll_time32
303     o32     unshare                         sys_unshare
304     o32     splice                          sys_splice
305     o32     sync_file_range                 sys_sync_file_range             sys32_sync_file_range
306     o32     tee                             sys_tee
307     o32     vmsplice                        sys_vmsplice
308     o32     move_pages                      sys_move_pages
309     o32     set_robust_list                 sys_set_robust_list             compat_sys_set_robust_list
310     o32     get_robust_list                 sys_get_robust_list             compat_sys_get_robust_list
311     o32     kexec_load                      sys_kexec_load                  compat_sys_kexec_load
312     o32     getcpu                          sys_getcpu
313     o32     epoll_pwait                     sys_epoll_pwait                 compat_sys_epoll_pwait
314     o32     ioprio_set                      sys_ioprio_set
315     o32     ioprio_get                      sys_ioprio_get
316     o32     utimensat                       sys_utimensat_time32
317     o32     signalfd                        sys_signalfd                    compat_sys_signalfd
318     o32     timerfd                         sys_ni_syscall
319     o32     eventfd                         sys_eventfd
320     o32     fallocate                       sys_fallocate                   sys32_fallocate
321     o32     timerfd_create                  sys_timerfd_create
322     o32     timerfd_gettime                 sys_timerfd_gettime32
323     o32     timerfd_settime                 sys_timerfd_settime32
324     o32     signalfd4                       sys_signalfd4                   compat_sys_signalfd4
325     o32     eventfd2                        sys_eventfd2
326     o32     epoll_create1                   sys_epoll_create1
327     o32     dup3                            sys_dup3
328     o32     pipe2                           sys_pipe2
329     o32     inotify_init1                   sys_inotify_init1
330     o32     preadv                          sys_preadv                      compat_sys_preadv
331     o32     pwritev                         sys_pwritev                     compat_sys_pwritev
332     o32     rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
333     o32     perf_event_open                 sys_perf_event_open
334     o32     accept4                         sys_accept4
335     o32     recvmmsg                        sys_recvmmsg_time32             compat_sys_recvmmsg_time32
336     o32     fanotify_init                   sys_fanotify_init
337     o32     fanotify_mark                   sys_fanotify_mark               compat_sys_fanotify_mark
338     o32     prlimit64                       sys_prlimit64
339     o32     name_to_handle_at               sys_name_to_handle_at
340     o32     open_by_handle_at               sys_open_by_handle_at           compat_sys_open_by_handle_at
341     o32     clock_adjtime                   sys_clock_adjtime32
342     o32     syncfs                          sys_syncfs
343     o32     sendmmsg                        sys_sendmmsg                    compat_sys_sendmmsg
344     o32     setns                           sys_setns
345     o32     process_vm_readv                sys_process_vm_readv
346     o32     process_vm_writev               sys_process_vm_writev
347     o32     kcmp                            sys_kcmp
348     o32     finit_module                    sys_finit_module
349     o32     sched_setattr                   sys_sched_setattr
350     o32     sched_getattr                   sys_sched_getattr
351     o32     renameat2                       sys_renameat2
352     o32     seccomp                         sys_seccomp
353     o32     getrandom                       sys_getrandom
354     o32     memfd_create                    sys_memfd_create
355     o32     bpf                             sys_bpf
356     o32     execveat                        sys_execveat                    compat_sys_execveat
357     o32     userfaultfd                     sys_userfaultfd
358     o32     membarrier                      sys_membarrier
359     o32     mlock2                          sys_mlock2
360     o32     copy_file_range                 sys_copy_file_range
361     o32     preadv2                         sys_preadv2                     compat_sys_preadv2
362     o32     pwritev2                        sys_pwritev2                    compat_sys_pwritev2
363     o32     pkey_mprotect                   sys_pkey_mprotect
364     o32     pkey_alloc                      sys_pkey_alloc
365     o32     pkey_free                       sys_pkey_free
366     o32     statx                           sys_statx
367     o32     rseq                            sys_rseq
368     o32     io_pgetevents                   sys_io_pgetevents_time32        compat_sys_io_pgetevents
393     o32     semget                          sys_semget
394     o32     semctl                          sys_semctl                      compat_sys_semctl
395     o32     shmget                          sys_shmget
396     o32     shmctl                          sys_shmctl                      compat_sys_shmctl
397     o32     shmat                           sys_shmat                       compat_sys_shmat
398     o32     shmdt                           sys_shmdt
399     o32     msgget                          sys_msgget
400     o32     msgsnd                          sys_msgsnd                      compat_sys_msgsnd
401     o32     msgrcv                          sys_msgrcv                      compat_sys_msgrcv
402     o32     msgctl                          sys_msgctl                      compat_sys_msgctl
403     o32     clock_gettime64                 sys_clock_gettime               sys_clock_gettime
404     o32     clock_settime64                 sys_clock_settime               sys_clock_settime
405     o32     clock_adjtime64                 sys_clock_adjtime               sys_clock_adjtime
406     o32     clock_getres_time64             sys_clock_getres                sys_clock_getres
407     o32     clock_nanosleep_time64          sys_clock_nanosleep             sys_clock_nanosleep
408     o32     timer_gettime64                 sys_timer_gettime               sys_timer_gettime
409     o32     timer_settime64                 sys_timer_settime               sys_timer_settime
410     o32     timerfd_gettime64               sys_timerfd_gettime             sys_timerfd_gettime
411     o32     timerfd_settime64               sys_timerfd_settime             sys_timerfd_settime
412     o32     utimensat_time64                sys_utimensat                   sys_utimensat
413     o32     pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     o32     ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     o32     io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     o32     recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     o32     mq_timedsend_time64             sys_mq_timedsend                sys_mq_timedsend
419     o32     mq_timedreceive_time64          sys_mq_timedreceive             sys_mq_timedreceive
420     o32     semtimedop_time64               sys_semtimedop                  sys_semtimedop
421     o32     rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     o32     futex_time64                    sys_futex                       sys_futex
423     o32     sched_rr_get_interval_time64    sys_sched_rr_get_interval       sys_sched_rr_get_interval
424     o32     pidfd_send_signal               sys_pidfd_send_signal
425     o32     io_uring_setup                  sys_io_uring_setup
426     o32     io_uring_enter                  sys_io_uring_enter
427     o32     io_uring_register               sys_io_uring_register
428     o32     open_tree                       sys_open_tree
429     o32     move_mount                      sys_move_mount
430     o32     fsopen                          sys_fsopen
431     o32     fsconfig                        sys_fsconfig
432     o32     fsmount                         sys_fsmount
433     o32     fspick                          sys_fspick
434     o32     pidfd_open                      sys_pidfd_open
435     o32     clone3                          __sys_clone3
436     o32     close_range                     sys_close_range
437     o32     openat2                         sys_openat2
438     o32     pidfd_getfd                     sys_pidfd_getfd
439     o32     faccessat2                      sys_faccessat2
440     o32     process_madvise                 sys_process_madvise
441     o32     epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     o32     mount_setattr                   sys_mount_setattr
443     o32     quotactl_fd                     sys_quotactl_fd
444     o32     landlock_create_ruleset         sys_landlock_create_ruleset
445     o32     landlock_add_rule               sys_landlock_add_rule
446     o32     landlock_restrict_self          sys_landlock_restrict_self
448     o32     process_mrelease                sys_process_mrelease
449     o32     futex_waitv                     sys_futex_waitv
450     o32     set_mempolicy_home_node         sys_set_mempolicy_home_node
451     o32     cachestat                       sys_cachestat
452     o32     fchmodat2                       sys_fchmodat2
453     o32     map_shadow_stack                sys_map_shadow_stack
454     o32     futex_wake                      sys_futex_wake
455     o32     futex_wait                      sys_futex_wait
456     o32     futex_requeue                   sys_futex_requeue
457     o32     statmount                       sys_statmount
458     o32     listmount                       sys_listmount
459     o32     lsm_get_self_attr               sys_lsm_get_self_attr
460     o32     lsm_set_self_attr               sys_lsm_set_self_attr
461     o32     lsm_list_modules                sys_lsm_list_modules
462     o32     mseal                           sys_mseal
463     o32     setxattrat                      sys_setxattrat
464     o32     getxattrat                      sys_getxattrat
465     o32     listxattrat                     sys_listxattrat
466     o32     removexattrat                   sys_removexattrat
467     o32     open_tree_attr                  sys_open_tree_attr
468     o32     file_getattr                    sys_file_getattr
469     o32     file_setattr                    sys_file_setattr
470     o32     listns                          sys_listns
471     o32     rseq_slice_yield                sys_rseq_slice_yield
"""


# MIPS n32 (default ABI, present in /lib32)
# - arch/mips/kernel/syscalls/syscall_n32.tbl
mips_n32_syscall_tbl = """
0       n32     read                            sys_read
1       n32     write                           sys_write
2       n32     open                            sys_open
3       n32     close                           sys_close
4       n32     stat                            sys_newstat
5       n32     fstat                           sys_newfstat
6       n32     lstat                           sys_newlstat
7       n32     poll                            sys_poll
8       n32     lseek                           sys_lseek
9       n32     mmap                            sys_mips_mmap
10      n32     mprotect                        sys_mprotect
11      n32     munmap                          sys_munmap
12      n32     brk                             sys_brk
13      n32     rt_sigaction                    compat_sys_rt_sigaction
14      n32     rt_sigprocmask                  compat_sys_rt_sigprocmask
15      n32     ioctl                           compat_sys_ioctl
16      n32     pread64                         sys_pread64
17      n32     pwrite64                        sys_pwrite64
18      n32     readv                           sys_readv
19      n32     writev                          sys_writev
20      n32     access                          sys_access
21      n32     pipe                            sysm_pipe
22      n32     _newselect                      compat_sys_select
23      n32     sched_yield                     sys_sched_yield
24      n32     mremap                          sys_mremap
25      n32     msync                           sys_msync
26      n32     mincore                         sys_mincore
27      n32     madvise                         sys_madvise
28      n32     shmget                          sys_shmget
29      n32     shmat                           sys_shmat
30      n32     shmctl                          compat_sys_old_shmctl
31      n32     dup                             sys_dup
32      n32     dup2                            sys_dup2
33      n32     pause                           sys_pause
34      n32     nanosleep                       sys_nanosleep_time32
35      n32     getitimer                       compat_sys_getitimer
36      n32     setitimer                       compat_sys_setitimer
37      n32     alarm                           sys_alarm
38      n32     getpid                          sys_getpid
39      n32     sendfile                        compat_sys_sendfile
40      n32     socket                          sys_socket
41      n32     connect                         sys_connect
42      n32     accept                          sys_accept
43      n32     sendto                          sys_sendto
44      n32     recvfrom                        compat_sys_recvfrom
45      n32     sendmsg                         compat_sys_sendmsg
46      n32     recvmsg                         compat_sys_recvmsg
47      n32     shutdown                        sys_shutdown
48      n32     bind                            sys_bind
49      n32     listen                          sys_listen
50      n32     getsockname                     sys_getsockname
51      n32     getpeername                     sys_getpeername
52      n32     socketpair                      sys_socketpair
53      n32     setsockopt                      sys_setsockopt
54      n32     getsockopt                      sys_getsockopt
55      n32     clone                           __sys_clone
56      n32     fork                            __sys_fork
57      n32     execve                          compat_sys_execve
58      n32     exit                            sys_exit
59      n32     wait4                           compat_sys_wait4
60      n32     kill                            sys_kill
61      n32     uname                           sys_newuname
62      n32     semget                          sys_semget
63      n32     semop                           sys_semop
64      n32     semctl                          compat_sys_old_semctl
65      n32     shmdt                           sys_shmdt
66      n32     msgget                          sys_msgget
67      n32     msgsnd                          compat_sys_msgsnd
68      n32     msgrcv                          compat_sys_msgrcv
69      n32     msgctl                          compat_sys_old_msgctl
70      n32     fcntl                           compat_sys_fcntl
71      n32     flock                           sys_flock
72      n32     fsync                           sys_fsync
73      n32     fdatasync                       sys_fdatasync
74      n32     truncate                        sys_truncate
75      n32     ftruncate                       sys_ftruncate
76      n32     getdents                        compat_sys_getdents
77      n32     getcwd                          sys_getcwd
78      n32     chdir                           sys_chdir
79      n32     fchdir                          sys_fchdir
80      n32     rename                          sys_rename
81      n32     mkdir                           sys_mkdir
82      n32     rmdir                           sys_rmdir
83      n32     creat                           sys_creat
84      n32     link                            sys_link
85      n32     unlink                          sys_unlink
86      n32     symlink                         sys_symlink
87      n32     readlink                        sys_readlink
88      n32     chmod                           sys_chmod
89      n32     fchmod                          sys_fchmod
90      n32     chown                           sys_chown
91      n32     fchown                          sys_fchown
92      n32     lchown                          sys_lchown
93      n32     umask                           sys_umask
94      n32     gettimeofday                    compat_sys_gettimeofday
95      n32     getrlimit                       compat_sys_getrlimit
96      n32     getrusage                       compat_sys_getrusage
97      n32     sysinfo                         compat_sys_sysinfo
98      n32     times                           compat_sys_times
99      n32     ptrace                          compat_sys_ptrace
100     n32     getuid                          sys_getuid
101     n32     syslog                          sys_syslog
102     n32     getgid                          sys_getgid
103     n32     setuid                          sys_setuid
104     n32     setgid                          sys_setgid
105     n32     geteuid                         sys_geteuid
106     n32     getegid                         sys_getegid
107     n32     setpgid                         sys_setpgid
108     n32     getppid                         sys_getppid
109     n32     getpgrp                         sys_getpgrp
110     n32     setsid                          sys_setsid
111     n32     setreuid                        sys_setreuid
112     n32     setregid                        sys_setregid
113     n32     getgroups                       sys_getgroups
114     n32     setgroups                       sys_setgroups
115     n32     setresuid                       sys_setresuid
116     n32     getresuid                       sys_getresuid
117     n32     setresgid                       sys_setresgid
118     n32     getresgid                       sys_getresgid
119     n32     getpgid                         sys_getpgid
120     n32     setfsuid                        sys_setfsuid
121     n32     setfsgid                        sys_setfsgid
122     n32     getsid                          sys_getsid
123     n32     capget                          sys_capget
124     n32     capset                          sys_capset
125     n32     rt_sigpending                   compat_sys_rt_sigpending
126     n32     rt_sigtimedwait                 compat_sys_rt_sigtimedwait_time32
127     n32     rt_sigqueueinfo                 compat_sys_rt_sigqueueinfo
128     n32     rt_sigsuspend                   compat_sys_rt_sigsuspend
129     n32     sigaltstack                     compat_sys_sigaltstack
130     n32     utime                           sys_utime32
131     n32     mknod                           sys_mknod
132     n32     personality                     sys_32_personality
133     n32     ustat                           compat_sys_ustat
134     n32     statfs                          compat_sys_statfs
135     n32     fstatfs                         compat_sys_fstatfs
136     n32     sysfs                           sys_sysfs
137     n32     getpriority                     sys_getpriority
138     n32     setpriority                     sys_setpriority
139     n32     sched_setparam                  sys_sched_setparam
140     n32     sched_getparam                  sys_sched_getparam
141     n32     sched_setscheduler              sys_sched_setscheduler
142     n32     sched_getscheduler              sys_sched_getscheduler
143     n32     sched_get_priority_max          sys_sched_get_priority_max
144     n32     sched_get_priority_min          sys_sched_get_priority_min
145     n32     sched_rr_get_interval           sys_sched_rr_get_interval_time32
146     n32     mlock                           sys_mlock
147     n32     munlock                         sys_munlock
148     n32     mlockall                        sys_mlockall
149     n32     munlockall                      sys_munlockall
150     n32     vhangup                         sys_vhangup
151     n32     pivot_root                      sys_pivot_root
152     n32     _sysctl                         sys_ni_syscall
153     n32     prctl                           sys_prctl
154     n32     adjtimex                        sys_adjtimex_time32
155     n32     setrlimit                       compat_sys_setrlimit
156     n32     chroot                          sys_chroot
157     n32     sync                            sys_sync
158     n32     acct                            sys_acct
159     n32     settimeofday                    compat_sys_settimeofday
160     n32     mount                           sys_mount
161     n32     umount2                         sys_umount
162     n32     swapon                          sys_swapon
163     n32     swapoff                         sys_swapoff
164     n32     reboot                          sys_reboot
165     n32     sethostname                     sys_sethostname
166     n32     setdomainname                   sys_setdomainname
167     n32     create_module                   sys_ni_syscall
168     n32     init_module                     sys_init_module
169     n32     delete_module                   sys_delete_module
170     n32     get_kernel_syms                 sys_ni_syscall
171     n32     query_module                    sys_ni_syscall
172     n32     quotactl                        sys_quotactl
173     n32     nfsservctl                      sys_ni_syscall
174     n32     getpmsg                         sys_ni_syscall
175     n32     putpmsg                         sys_ni_syscall
176     n32     afs_syscall                     sys_ni_syscall
177     n32     reserved177                     sys_ni_syscall
178     n32     gettid                          sys_gettid
179     n32     readahead                       sys_readahead
180     n32     setxattr                        sys_setxattr
181     n32     lsetxattr                       sys_lsetxattr
182     n32     fsetxattr                       sys_fsetxattr
183     n32     getxattr                        sys_getxattr
184     n32     lgetxattr                       sys_lgetxattr
185     n32     fgetxattr                       sys_fgetxattr
186     n32     listxattr                       sys_listxattr
187     n32     llistxattr                      sys_llistxattr
188     n32     flistxattr                      sys_flistxattr
189     n32     removexattr                     sys_removexattr
190     n32     lremovexattr                    sys_lremovexattr
191     n32     fremovexattr                    sys_fremovexattr
192     n32     tkill                           sys_tkill
193     n32     reserved193                     sys_ni_syscall
194     n32     futex                           sys_futex_time32
195     n32     sched_setaffinity               compat_sys_sched_setaffinity
196     n32     sched_getaffinity               compat_sys_sched_getaffinity
197     n32     cacheflush                      sys_cacheflush
198     n32     cachectl                        sys_cachectl
199     n32     sysmips                         __sys_sysmips
200     n32     io_setup                        compat_sys_io_setup
201     n32     io_destroy                      sys_io_destroy
202     n32     io_getevents                    sys_io_getevents_time32
203     n32     io_submit                       compat_sys_io_submit
204     n32     io_cancel                       sys_io_cancel
205     n32     exit_group                      sys_exit_group
206     n32     lookup_dcookie                  sys_ni_syscall
207     n32     epoll_create                    sys_epoll_create
208     n32     epoll_ctl                       sys_epoll_ctl
209     n32     epoll_wait                      sys_epoll_wait
210     n32     remap_file_pages                sys_remap_file_pages
211     n32     rt_sigreturn                    sysn32_rt_sigreturn
212     n32     fcntl64                         compat_sys_fcntl64
213     n32     set_tid_address                 sys_set_tid_address
214     n32     restart_syscall                 sys_restart_syscall
215     n32     semtimedop                      sys_semtimedop_time32
216     n32     fadvise64                       sys_fadvise64_64
217     n32     statfs64                        compat_sys_statfs64
218     n32     fstatfs64                       compat_sys_fstatfs64
219     n32     sendfile64                      sys_sendfile64
220     n32     timer_create                    compat_sys_timer_create
221     n32     timer_settime                   sys_timer_settime32
222     n32     timer_gettime                   sys_timer_gettime32
223     n32     timer_getoverrun                sys_timer_getoverrun
224     n32     timer_delete                    sys_timer_delete
225     n32     clock_settime                   sys_clock_settime32
226     n32     clock_gettime                   sys_clock_gettime32
227     n32     clock_getres                    sys_clock_getres_time32
228     n32     clock_nanosleep                 sys_clock_nanosleep_time32
229     n32     tgkill                          sys_tgkill
230     n32     utimes                          sys_utimes_time32
231     n32     mbind                           sys_mbind
232     n32     get_mempolicy                   sys_get_mempolicy
233     n32     set_mempolicy                   sys_set_mempolicy
234     n32     mq_open                         compat_sys_mq_open
235     n32     mq_unlink                       sys_mq_unlink
236     n32     mq_timedsend                    sys_mq_timedsend_time32
237     n32     mq_timedreceive                 sys_mq_timedreceive_time32
238     n32     mq_notify                       compat_sys_mq_notify
239     n32     mq_getsetattr                   compat_sys_mq_getsetattr
240     n32     vserver                         sys_ni_syscall
241     n32     waitid                          compat_sys_waitid
243     n32     add_key                         sys_add_key
244     n32     request_key                     sys_request_key
245     n32     keyctl                          compat_sys_keyctl
246     n32     set_thread_area                 sys_set_thread_area
247     n32     inotify_init                    sys_inotify_init
248     n32     inotify_add_watch               sys_inotify_add_watch
249     n32     inotify_rm_watch                sys_inotify_rm_watch
250     n32     migrate_pages                   sys_migrate_pages
251     n32     openat                          sys_openat
252     n32     mkdirat                         sys_mkdirat
253     n32     mknodat                         sys_mknodat
254     n32     fchownat                        sys_fchownat
255     n32     futimesat                       sys_futimesat_time32
256     n32     newfstatat                      sys_newfstatat
257     n32     unlinkat                        sys_unlinkat
258     n32     renameat                        sys_renameat
259     n32     linkat                          sys_linkat
260     n32     symlinkat                       sys_symlinkat
261     n32     readlinkat                      sys_readlinkat
262     n32     fchmodat                        sys_fchmodat
263     n32     faccessat                       sys_faccessat
264     n32     pselect6                        compat_sys_pselect6_time32
265     n32     ppoll                           compat_sys_ppoll_time32
266     n32     unshare                         sys_unshare
267     n32     splice                          sys_splice
268     n32     sync_file_range                 sys_sync_file_range
269     n32     tee                             sys_tee
270     n32     vmsplice                        sys_vmsplice
271     n32     move_pages                      sys_move_pages
272     n32     set_robust_list                 compat_sys_set_robust_list
273     n32     get_robust_list                 compat_sys_get_robust_list
274     n32     kexec_load                      compat_sys_kexec_load
275     n32     getcpu                          sys_getcpu
276     n32     epoll_pwait                     compat_sys_epoll_pwait
277     n32     ioprio_set                      sys_ioprio_set
278     n32     ioprio_get                      sys_ioprio_get
279     n32     utimensat                       sys_utimensat_time32
280     n32     signalfd                        compat_sys_signalfd
281     n32     timerfd                         sys_ni_syscall
282     n32     eventfd                         sys_eventfd
283     n32     fallocate                       sys_fallocate
284     n32     timerfd_create                  sys_timerfd_create
285     n32     timerfd_gettime                 sys_timerfd_gettime32
286     n32     timerfd_settime                 sys_timerfd_settime32
287     n32     signalfd4                       compat_sys_signalfd4
288     n32     eventfd2                        sys_eventfd2
289     n32     epoll_create1                   sys_epoll_create1
290     n32     dup3                            sys_dup3
291     n32     pipe2                           sys_pipe2
292     n32     inotify_init1                   sys_inotify_init1
293     n32     preadv                          compat_sys_preadv
294     n32     pwritev                         compat_sys_pwritev
295     n32     rt_tgsigqueueinfo               compat_sys_rt_tgsigqueueinfo
296     n32     perf_event_open                 sys_perf_event_open
297     n32     accept4                         sys_accept4
298     n32     recvmmsg                        compat_sys_recvmmsg_time32
299     n32     getdents64                      sys_getdents64
300     n32     fanotify_init                   sys_fanotify_init
301     n32     fanotify_mark                   sys_fanotify_mark
302     n32     prlimit64                       sys_prlimit64
303     n32     name_to_handle_at               sys_name_to_handle_at
304     n32     open_by_handle_at               sys_open_by_handle_at
305     n32     clock_adjtime                   sys_clock_adjtime32
306     n32     syncfs                          sys_syncfs
307     n32     sendmmsg                        compat_sys_sendmmsg
308     n32     setns                           sys_setns
309     n32     process_vm_readv                sys_process_vm_readv
310     n32     process_vm_writev               sys_process_vm_writev
311     n32     kcmp                            sys_kcmp
312     n32     finit_module                    sys_finit_module
313     n32     sched_setattr                   sys_sched_setattr
314     n32     sched_getattr                   sys_sched_getattr
315     n32     renameat2                       sys_renameat2
316     n32     seccomp                         sys_seccomp
317     n32     getrandom                       sys_getrandom
318     n32     memfd_create                    sys_memfd_create
319     n32     bpf                             sys_bpf
320     n32     execveat                        compat_sys_execveat
321     n32     userfaultfd                     sys_userfaultfd
322     n32     membarrier                      sys_membarrier
323     n32     mlock2                          sys_mlock2
324     n32     copy_file_range                 sys_copy_file_range
325     n32     preadv2                         compat_sys_preadv2
326     n32     pwritev2                        compat_sys_pwritev2
327     n32     pkey_mprotect                   sys_pkey_mprotect
328     n32     pkey_alloc                      sys_pkey_alloc
329     n32     pkey_free                       sys_pkey_free
330     n32     statx                           sys_statx
331     n32     rseq                            sys_rseq
332     n32     io_pgetevents                   compat_sys_io_pgetevents
403     n32     clock_gettime64                 sys_clock_gettime
404     n32     clock_settime64                 sys_clock_settime
405     n32     clock_adjtime64                 sys_clock_adjtime
406     n32     clock_getres_time64             sys_clock_getres
407     n32     clock_nanosleep_time64          sys_clock_nanosleep
408     n32     timer_gettime64                 sys_timer_gettime
409     n32     timer_settime64                 sys_timer_settime
410     n32     timerfd_gettime64               sys_timerfd_gettime
411     n32     timerfd_settime64               sys_timerfd_settime
412     n32     utimensat_time64                sys_utimensat
413     n32     pselect6_time64                 compat_sys_pselect6_time64
414     n32     ppoll_time64                    compat_sys_ppoll_time64
416     n32     io_pgetevents_time64            compat_sys_io_pgetevents_time64
417     n32     recvmmsg_time64                 compat_sys_recvmmsg_time64
418     n32     mq_timedsend_time64             sys_mq_timedsend
419     n32     mq_timedreceive_time64          sys_mq_timedreceive
420     n32     semtimedop_time64               sys_semtimedop
421     n32     rt_sigtimedwait_time64          compat_sys_rt_sigtimedwait_time64
422     n32     futex_time64                    sys_futex
423     n32     sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     n32     pidfd_send_signal               sys_pidfd_send_signal
425     n32     io_uring_setup                  sys_io_uring_setup
426     n32     io_uring_enter                  sys_io_uring_enter
427     n32     io_uring_register               sys_io_uring_register
428     n32     open_tree                       sys_open_tree
429     n32     move_mount                      sys_move_mount
430     n32     fsopen                          sys_fsopen
431     n32     fsconfig                        sys_fsconfig
432     n32     fsmount                         sys_fsmount
433     n32     fspick                          sys_fspick
434     n32     pidfd_open                      sys_pidfd_open
435     n32     clone3                          __sys_clone3
436     n32     close_range                     sys_close_range
437     n32     openat2                         sys_openat2
438     n32     pidfd_getfd                     sys_pidfd_getfd
439     n32     faccessat2                      sys_faccessat2
440     n32     process_madvise                 sys_process_madvise
441     n32     epoll_pwait2                    compat_sys_epoll_pwait2
442     n32     mount_setattr                   sys_mount_setattr
443     n32     quotactl_fd                     sys_quotactl_fd
444     n32     landlock_create_ruleset         sys_landlock_create_ruleset
445     n32     landlock_add_rule               sys_landlock_add_rule
446     n32     landlock_restrict_self          sys_landlock_restrict_self
448     n32     process_mrelease                sys_process_mrelease
449     n32     futex_waitv                     sys_futex_waitv
450     n32     set_mempolicy_home_node         sys_set_mempolicy_home_node
451     n32     cachestat                       sys_cachestat
452     n32     fchmodat2                       sys_fchmodat2
453     n32     map_shadow_stack                sys_map_shadow_stack
454     n32     futex_wake                      sys_futex_wake
455     n32     futex_wait                      sys_futex_wait
456     n32     futex_requeue                   sys_futex_requeue
457     n32     statmount                       sys_statmount
458     n32     listmount                       sys_listmount
459     n32     lsm_get_self_attr               sys_lsm_get_self_attr
460     n32     lsm_set_self_attr               sys_lsm_set_self_attr
461     n32     lsm_list_modules                sys_lsm_list_modules
462     n32     mseal                           sys_mseal
463     n32     setxattrat                      sys_setxattrat
464     n32     getxattrat                      sys_getxattrat
465     n32     listxattrat                     sys_listxattrat
466     n32     removexattrat                   sys_removexattrat
467     n32     open_tree_attr                  sys_open_tree_attr
468     n32     file_getattr                    sys_file_getattr
469     n32     file_setattr                    sys_file_setattr
470     n32     listns                          sys_listns
471     n32     rseq_slice_yield                sys_rseq_slice_yield
"""


# MIPS n64 (for 64-bit ABI, present in /lib64)
# - arch/mips/kernel/syscalls/syscall_n64.tbl
mips_n64_syscall_tbl = """
0       n64     read                            sys_read
1       n64     write                           sys_write
2       n64     open                            sys_open
3       n64     close                           sys_close
4       n64     stat                            sys_newstat
5       n64     fstat                           sys_newfstat
6       n64     lstat                           sys_newlstat
7       n64     poll                            sys_poll
8       n64     lseek                           sys_lseek
9       n64     mmap                            sys_mips_mmap
10      n64     mprotect                        sys_mprotect
11      n64     munmap                          sys_munmap
12      n64     brk                             sys_brk
13      n64     rt_sigaction                    sys_rt_sigaction
14      n64     rt_sigprocmask                  sys_rt_sigprocmask
15      n64     ioctl                           sys_ioctl
16      n64     pread64                         sys_pread64
17      n64     pwrite64                        sys_pwrite64
18      n64     readv                           sys_readv
19      n64     writev                          sys_writev
20      n64     access                          sys_access
21      n64     pipe                            sysm_pipe
22      n64     _newselect                      sys_select
23      n64     sched_yield                     sys_sched_yield
24      n64     mremap                          sys_mremap
25      n64     msync                           sys_msync
26      n64     mincore                         sys_mincore
27      n64     madvise                         sys_madvise
28      n64     shmget                          sys_shmget
29      n64     shmat                           sys_shmat
30      n64     shmctl                          sys_old_shmctl
31      n64     dup                             sys_dup
32      n64     dup2                            sys_dup2
33      n64     pause                           sys_pause
34      n64     nanosleep                       sys_nanosleep
35      n64     getitimer                       sys_getitimer
36      n64     setitimer                       sys_setitimer
37      n64     alarm                           sys_alarm
38      n64     getpid                          sys_getpid
39      n64     sendfile                        sys_sendfile64
40      n64     socket                          sys_socket
41      n64     connect                         sys_connect
42      n64     accept                          sys_accept
43      n64     sendto                          sys_sendto
44      n64     recvfrom                        sys_recvfrom
45      n64     sendmsg                         sys_sendmsg
46      n64     recvmsg                         sys_recvmsg
47      n64     shutdown                        sys_shutdown
48      n64     bind                            sys_bind
49      n64     listen                          sys_listen
50      n64     getsockname                     sys_getsockname
51      n64     getpeername                     sys_getpeername
52      n64     socketpair                      sys_socketpair
53      n64     setsockopt                      sys_setsockopt
54      n64     getsockopt                      sys_getsockopt
55      n64     clone                           __sys_clone
56      n64     fork                            __sys_fork
57      n64     execve                          sys_execve
58      n64     exit                            sys_exit
59      n64     wait4                           sys_wait4
60      n64     kill                            sys_kill
61      n64     uname                           sys_newuname
62      n64     semget                          sys_semget
63      n64     semop                           sys_semop
64      n64     semctl                          sys_old_semctl
65      n64     shmdt                           sys_shmdt
66      n64     msgget                          sys_msgget
67      n64     msgsnd                          sys_msgsnd
68      n64     msgrcv                          sys_msgrcv
69      n64     msgctl                          sys_old_msgctl
70      n64     fcntl                           sys_fcntl
71      n64     flock                           sys_flock
72      n64     fsync                           sys_fsync
73      n64     fdatasync                       sys_fdatasync
74      n64     truncate                        sys_truncate
75      n64     ftruncate                       sys_ftruncate
76      n64     getdents                        sys_getdents
77      n64     getcwd                          sys_getcwd
78      n64     chdir                           sys_chdir
79      n64     fchdir                          sys_fchdir
80      n64     rename                          sys_rename
81      n64     mkdir                           sys_mkdir
82      n64     rmdir                           sys_rmdir
83      n64     creat                           sys_creat
84      n64     link                            sys_link
85      n64     unlink                          sys_unlink
86      n64     symlink                         sys_symlink
87      n64     readlink                        sys_readlink
88      n64     chmod                           sys_chmod
89      n64     fchmod                          sys_fchmod
90      n64     chown                           sys_chown
91      n64     fchown                          sys_fchown
92      n64     lchown                          sys_lchown
93      n64     umask                           sys_umask
94      n64     gettimeofday                    sys_gettimeofday
95      n64     getrlimit                       sys_getrlimit
96      n64     getrusage                       sys_getrusage
97      n64     sysinfo                         sys_sysinfo
98      n64     times                           sys_times
99      n64     ptrace                          sys_ptrace
100     n64     getuid                          sys_getuid
101     n64     syslog                          sys_syslog
102     n64     getgid                          sys_getgid
103     n64     setuid                          sys_setuid
104     n64     setgid                          sys_setgid
105     n64     geteuid                         sys_geteuid
106     n64     getegid                         sys_getegid
107     n64     setpgid                         sys_setpgid
108     n64     getppid                         sys_getppid
109     n64     getpgrp                         sys_getpgrp
110     n64     setsid                          sys_setsid
111     n64     setreuid                        sys_setreuid
112     n64     setregid                        sys_setregid
113     n64     getgroups                       sys_getgroups
114     n64     setgroups                       sys_setgroups
115     n64     setresuid                       sys_setresuid
116     n64     getresuid                       sys_getresuid
117     n64     setresgid                       sys_setresgid
118     n64     getresgid                       sys_getresgid
119     n64     getpgid                         sys_getpgid
120     n64     setfsuid                        sys_setfsuid
121     n64     setfsgid                        sys_setfsgid
122     n64     getsid                          sys_getsid
123     n64     capget                          sys_capget
124     n64     capset                          sys_capset
125     n64     rt_sigpending                   sys_rt_sigpending
126     n64     rt_sigtimedwait                 sys_rt_sigtimedwait
127     n64     rt_sigqueueinfo                 sys_rt_sigqueueinfo
128     n64     rt_sigsuspend                   sys_rt_sigsuspend
129     n64     sigaltstack                     sys_sigaltstack
130     n64     utime                           sys_utime
131     n64     mknod                           sys_mknod
132     n64     personality                     sys_personality
133     n64     ustat                           sys_ustat
134     n64     statfs                          sys_statfs
135     n64     fstatfs                         sys_fstatfs
136     n64     sysfs                           sys_sysfs
137     n64     getpriority                     sys_getpriority
138     n64     setpriority                     sys_setpriority
139     n64     sched_setparam                  sys_sched_setparam
140     n64     sched_getparam                  sys_sched_getparam
141     n64     sched_setscheduler              sys_sched_setscheduler
142     n64     sched_getscheduler              sys_sched_getscheduler
143     n64     sched_get_priority_max          sys_sched_get_priority_max
144     n64     sched_get_priority_min          sys_sched_get_priority_min
145     n64     sched_rr_get_interval           sys_sched_rr_get_interval
146     n64     mlock                           sys_mlock
147     n64     munlock                         sys_munlock
148     n64     mlockall                        sys_mlockall
149     n64     munlockall                      sys_munlockall
150     n64     vhangup                         sys_vhangup
151     n64     pivot_root                      sys_pivot_root
152     n64     _sysctl                         sys_ni_syscall
153     n64     prctl                           sys_prctl
154     n64     adjtimex                        sys_adjtimex
155     n64     setrlimit                       sys_setrlimit
156     n64     chroot                          sys_chroot
157     n64     sync                            sys_sync
158     n64     acct                            sys_acct
159     n64     settimeofday                    sys_settimeofday
160     n64     mount                           sys_mount
161     n64     umount2                         sys_umount
162     n64     swapon                          sys_swapon
163     n64     swapoff                         sys_swapoff
164     n64     reboot                          sys_reboot
165     n64     sethostname                     sys_sethostname
166     n64     setdomainname                   sys_setdomainname
167     n64     create_module                   sys_ni_syscall
168     n64     init_module                     sys_init_module
169     n64     delete_module                   sys_delete_module
170     n64     get_kernel_syms                 sys_ni_syscall
171     n64     query_module                    sys_ni_syscall
172     n64     quotactl                        sys_quotactl
173     n64     nfsservctl                      sys_ni_syscall
174     n64     getpmsg                         sys_ni_syscall
175     n64     putpmsg                         sys_ni_syscall
176     n64     afs_syscall                     sys_ni_syscall
177     n64     reserved177                     sys_ni_syscall
178     n64     gettid                          sys_gettid
179     n64     readahead                       sys_readahead
180     n64     setxattr                        sys_setxattr
181     n64     lsetxattr                       sys_lsetxattr
182     n64     fsetxattr                       sys_fsetxattr
183     n64     getxattr                        sys_getxattr
184     n64     lgetxattr                       sys_lgetxattr
185     n64     fgetxattr                       sys_fgetxattr
186     n64     listxattr                       sys_listxattr
187     n64     llistxattr                      sys_llistxattr
188     n64     flistxattr                      sys_flistxattr
189     n64     removexattr                     sys_removexattr
190     n64     lremovexattr                    sys_lremovexattr
191     n64     fremovexattr                    sys_fremovexattr
192     n64     tkill                           sys_tkill
193     n64     reserved193                     sys_ni_syscall
194     n64     futex                           sys_futex
195     n64     sched_setaffinity               sys_sched_setaffinity
196     n64     sched_getaffinity               sys_sched_getaffinity
197     n64     cacheflush                      sys_cacheflush
198     n64     cachectl                        sys_cachectl
199     n64     sysmips                         __sys_sysmips
200     n64     io_setup                        sys_io_setup
201     n64     io_destroy                      sys_io_destroy
202     n64     io_getevents                    sys_io_getevents
203     n64     io_submit                       sys_io_submit
204     n64     io_cancel                       sys_io_cancel
205     n64     exit_group                      sys_exit_group
206     n64     lookup_dcookie                  sys_ni_syscall
207     n64     epoll_create                    sys_epoll_create
208     n64     epoll_ctl                       sys_epoll_ctl
209     n64     epoll_wait                      sys_epoll_wait
210     n64     remap_file_pages                sys_remap_file_pages
211     n64     rt_sigreturn                    sys_rt_sigreturn
212     n64     set_tid_address                 sys_set_tid_address
213     n64     restart_syscall                 sys_restart_syscall
214     n64     semtimedop                      sys_semtimedop
215     n64     fadvise64                       sys_fadvise64_64
216     n64     timer_create                    sys_timer_create
217     n64     timer_settime                   sys_timer_settime
218     n64     timer_gettime                   sys_timer_gettime
219     n64     timer_getoverrun                sys_timer_getoverrun
220     n64     timer_delete                    sys_timer_delete
221     n64     clock_settime                   sys_clock_settime
222     n64     clock_gettime                   sys_clock_gettime
223     n64     clock_getres                    sys_clock_getres
224     n64     clock_nanosleep                 sys_clock_nanosleep
225     n64     tgkill                          sys_tgkill
226     n64     utimes                          sys_utimes
227     n64     mbind                           sys_mbind
228     n64     get_mempolicy                   sys_get_mempolicy
229     n64     set_mempolicy                   sys_set_mempolicy
230     n64     mq_open                         sys_mq_open
231     n64     mq_unlink                       sys_mq_unlink
232     n64     mq_timedsend                    sys_mq_timedsend
233     n64     mq_timedreceive                 sys_mq_timedreceive
234     n64     mq_notify                       sys_mq_notify
235     n64     mq_getsetattr                   sys_mq_getsetattr
236     n64     vserver                         sys_ni_syscall
237     n64     waitid                          sys_waitid
239     n64     add_key                         sys_add_key
240     n64     request_key                     sys_request_key
241     n64     keyctl                          sys_keyctl
242     n64     set_thread_area                 sys_set_thread_area
243     n64     inotify_init                    sys_inotify_init
244     n64     inotify_add_watch               sys_inotify_add_watch
245     n64     inotify_rm_watch                sys_inotify_rm_watch
246     n64     migrate_pages                   sys_migrate_pages
247     n64     openat                          sys_openat
248     n64     mkdirat                         sys_mkdirat
249     n64     mknodat                         sys_mknodat
250     n64     fchownat                        sys_fchownat
251     n64     futimesat                       sys_futimesat
252     n64     newfstatat                      sys_newfstatat
253     n64     unlinkat                        sys_unlinkat
254     n64     renameat                        sys_renameat
255     n64     linkat                          sys_linkat
256     n64     symlinkat                       sys_symlinkat
257     n64     readlinkat                      sys_readlinkat
258     n64     fchmodat                        sys_fchmodat
259     n64     faccessat                       sys_faccessat
260     n64     pselect6                        sys_pselect6
261     n64     ppoll                           sys_ppoll
262     n64     unshare                         sys_unshare
263     n64     splice                          sys_splice
264     n64     sync_file_range                 sys_sync_file_range
265     n64     tee                             sys_tee
266     n64     vmsplice                        sys_vmsplice
267     n64     move_pages                      sys_move_pages
268     n64     set_robust_list                 sys_set_robust_list
269     n64     get_robust_list                 sys_get_robust_list
270     n64     kexec_load                      sys_kexec_load
271     n64     getcpu                          sys_getcpu
272     n64     epoll_pwait                     sys_epoll_pwait
273     n64     ioprio_set                      sys_ioprio_set
274     n64     ioprio_get                      sys_ioprio_get
275     n64     utimensat                       sys_utimensat
276     n64     signalfd                        sys_signalfd
277     n64     timerfd                         sys_ni_syscall
278     n64     eventfd                         sys_eventfd
279     n64     fallocate                       sys_fallocate
280     n64     timerfd_create                  sys_timerfd_create
281     n64     timerfd_gettime                 sys_timerfd_gettime
282     n64     timerfd_settime                 sys_timerfd_settime
283     n64     signalfd4                       sys_signalfd4
284     n64     eventfd2                        sys_eventfd2
285     n64     epoll_create1                   sys_epoll_create1
286     n64     dup3                            sys_dup3
287     n64     pipe2                           sys_pipe2
288     n64     inotify_init1                   sys_inotify_init1
289     n64     preadv                          sys_preadv
290     n64     pwritev                         sys_pwritev
291     n64     rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
292     n64     perf_event_open                 sys_perf_event_open
293     n64     accept4                         sys_accept4
294     n64     recvmmsg                        sys_recvmmsg
295     n64     fanotify_init                   sys_fanotify_init
296     n64     fanotify_mark                   sys_fanotify_mark
297     n64     prlimit64                       sys_prlimit64
298     n64     name_to_handle_at               sys_name_to_handle_at
299     n64     open_by_handle_at               sys_open_by_handle_at
300     n64     clock_adjtime                   sys_clock_adjtime
301     n64     syncfs                          sys_syncfs
302     n64     sendmmsg                        sys_sendmmsg
303     n64     setns                           sys_setns
304     n64     process_vm_readv                sys_process_vm_readv
305     n64     process_vm_writev               sys_process_vm_writev
306     n64     kcmp                            sys_kcmp
307     n64     finit_module                    sys_finit_module
308     n64     getdents64                      sys_getdents64
309     n64     sched_setattr                   sys_sched_setattr
310     n64     sched_getattr                   sys_sched_getattr
311     n64     renameat2                       sys_renameat2
312     n64     seccomp                         sys_seccomp
313     n64     getrandom                       sys_getrandom
314     n64     memfd_create                    sys_memfd_create
315     n64     bpf                             sys_bpf
316     n64     execveat                        sys_execveat
317     n64     userfaultfd                     sys_userfaultfd
318     n64     membarrier                      sys_membarrier
319     n64     mlock2                          sys_mlock2
320     n64     copy_file_range                 sys_copy_file_range
321     n64     preadv2                         sys_preadv2
322     n64     pwritev2                        sys_pwritev2
323     n64     pkey_mprotect                   sys_pkey_mprotect
324     n64     pkey_alloc                      sys_pkey_alloc
325     n64     pkey_free                       sys_pkey_free
326     n64     statx                           sys_statx
327     n64     rseq                            sys_rseq
328     n64     io_pgetevents                   sys_io_pgetevents
424     n64     pidfd_send_signal               sys_pidfd_send_signal
425     n64     io_uring_setup                  sys_io_uring_setup
426     n64     io_uring_enter                  sys_io_uring_enter
427     n64     io_uring_register               sys_io_uring_register
428     n64     open_tree                       sys_open_tree
429     n64     move_mount                      sys_move_mount
430     n64     fsopen                          sys_fsopen
431     n64     fsconfig                        sys_fsconfig
432     n64     fsmount                         sys_fsmount
433     n64     fspick                          sys_fspick
434     n64     pidfd_open                      sys_pidfd_open
435     n64     clone3                          __sys_clone3
436     n64     close_range                     sys_close_range
437     n64     openat2                         sys_openat2
438     n64     pidfd_getfd                     sys_pidfd_getfd
439     n64     faccessat2                      sys_faccessat2
440     n64     process_madvise                 sys_process_madvise
441     n64     epoll_pwait2                    sys_epoll_pwait2
442     n64     mount_setattr                   sys_mount_setattr
443     n64     quotactl_fd                     sys_quotactl_fd
444     n64     landlock_create_ruleset         sys_landlock_create_ruleset
445     n64     landlock_add_rule               sys_landlock_add_rule
446     n64     landlock_restrict_self          sys_landlock_restrict_self
448     n64     process_mrelease                sys_process_mrelease
449     n64     futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     n64     cachestat                       sys_cachestat
452     n64     fchmodat2                       sys_fchmodat2
453     n64     map_shadow_stack                sys_map_shadow_stack
454     n64     futex_wake                      sys_futex_wake
455     n64     futex_wait                      sys_futex_wait
456     n64     futex_requeue                   sys_futex_requeue
457     n64     statmount                       sys_statmount
458     n64     listmount                       sys_listmount
459     n64     lsm_get_self_attr               sys_lsm_get_self_attr
460     n64     lsm_set_self_attr               sys_lsm_set_self_attr
461     n64     lsm_list_modules                sys_lsm_list_modules
462     n64     mseal                           sys_mseal
463     n64     setxattrat                      sys_setxattrat
464     n64     getxattrat                      sys_getxattrat
465     n64     listxattrat                     sys_listxattrat
466     n64     removexattrat                   sys_removexattrat
467     n64     open_tree_attr                  sys_open_tree_attr
468     n64     file_getattr                    sys_file_getattr
469     n64     file_setattr                    sys_file_setattr
470     n64     listns                          sys_listns
471     n64     rseq_slice_yield                sys_rseq_slice_yield
"""


# PowerPC
# - arch/powerpc/kernel/syscalls/syscall.tbl
ppc_syscall_tbl = """
0       nospu   restart_syscall                 sys_restart_syscall
1       nospu   exit                            sys_exit
2       nospu   fork                            sys_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  open                            sys_open                        compat_sys_open
6       common  close                           sys_close
7       common  waitpid                         sys_waitpid
8       common  creat                           sys_creat
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      nospu   execve                          sys_execve                      compat_sys_execve
12      common  chdir                           sys_chdir
13      32      time                            sys_time32
13      64      time                            sys_time
13      spu     time                            sys_time
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
16      common  lchown                          sys_lchown
17      common  break                           sys_ni_syscall
18      32      oldstat                         sys_stat                        sys_ni_syscall
18      64      oldstat                         sys_ni_syscall
18      spu     oldstat                         sys_ni_syscall
19      common  lseek                           sys_lseek                       compat_sys_lseek
20      common  getpid                          sys_getpid
21      nospu   mount                           sys_mount
22      32      umount                          sys_oldumount
22      64      umount                          sys_ni_syscall
22      spu     umount                          sys_ni_syscall
23      common  setuid                          sys_setuid
24      common  getuid                          sys_getuid
25      32      stime                           sys_stime32
25      64      stime                           sys_stime
25      spu     stime                           sys_stime
26      nospu   ptrace                          sys_ptrace                      compat_sys_ptrace
27      common  alarm                           sys_alarm
28      32      oldfstat                        sys_fstat                       sys_ni_syscall
28      64      oldfstat                        sys_ni_syscall
28      spu     oldfstat                        sys_ni_syscall
29      nospu   pause                           sys_pause
30      32      utime                           sys_utime32
30      64      utime                           sys_utime
31      common  stty                            sys_ni_syscall
32      common  gtty                            sys_ni_syscall
33      common  access                          sys_access
34      common  nice                            sys_nice
35      common  ftime                           sys_ni_syscall
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  rename                          sys_rename
39      common  mkdir                           sys_mkdir
40      common  rmdir                           sys_rmdir
41      common  dup                             sys_dup
42      common  pipe                            sys_pipe
43      common  times                           sys_times                       compat_sys_times
44      common  prof                            sys_ni_syscall
45      common  brk                             sys_brk
46      common  setgid                          sys_setgid
47      common  getgid                          sys_getgid
48      nospu   signal                          sys_signal
49      common  geteuid                         sys_geteuid
50      common  getegid                         sys_getegid
51      nospu   acct                            sys_acct
52      nospu   umount2                         sys_umount
53      common  lock                            sys_ni_syscall
54      common  ioctl                           sys_ioctl                       compat_sys_ioctl
55      common  fcntl                           sys_fcntl                       compat_sys_fcntl
56      common  mpx                             sys_ni_syscall
57      common  setpgid                         sys_setpgid
58      common  ulimit                          sys_ni_syscall
59      32      oldolduname                     sys_olduname
59      64      oldolduname                     sys_ni_syscall
59      spu     oldolduname                     sys_ni_syscall
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      nospu   ustat                           sys_ustat                       compat_sys_ustat
63      common  dup2                            sys_dup2
64      common  getppid                         sys_getppid
65      common  getpgrp                         sys_getpgrp
66      common  setsid                          sys_setsid
67      32      sigaction                       sys_sigaction                   compat_sys_sigaction
67      64      sigaction                       sys_ni_syscall
67      spu     sigaction                       sys_ni_syscall
68      common  sgetmask                        sys_sgetmask
69      common  ssetmask                        sys_ssetmask
70      common  setreuid                        sys_setreuid
71      common  setregid                        sys_setregid
72      32      sigsuspend                      sys_sigsuspend
72      64      sigsuspend                      sys_ni_syscall
72      spu     sigsuspend                      sys_ni_syscall
73      32      sigpending                      sys_sigpending                  compat_sys_sigpending
73      64      sigpending                      sys_ni_syscall
73      spu     sigpending                      sys_ni_syscall
74      common  sethostname                     sys_sethostname
75      common  setrlimit                       sys_setrlimit                   compat_sys_setrlimit
76      32      getrlimit                       sys_old_getrlimit               compat_sys_old_getrlimit
76      64      getrlimit                       sys_ni_syscall
76      spu     getrlimit                       sys_ni_syscall
77      common  getrusage                       sys_getrusage                   compat_sys_getrusage
78      common  gettimeofday                    sys_gettimeofday                compat_sys_gettimeofday
79      common  settimeofday                    sys_settimeofday                compat_sys_settimeofday
80      common  getgroups                       sys_getgroups
81      common  setgroups                       sys_setgroups
82      32      select                          sys_old_select                  compat_sys_old_select
82      64      select                          sys_ni_syscall
82      spu     select                          sys_ni_syscall
83      common  symlink                         sys_symlink
84      32      oldlstat                        sys_lstat                       sys_ni_syscall
84      64      oldlstat                        sys_ni_syscall
84      spu     oldlstat                        sys_ni_syscall
85      common  readlink                        sys_readlink
86      nospu   uselib                          sys_uselib
87      nospu   swapon                          sys_swapon
88      nospu   reboot                          sys_reboot
89      32      readdir                         sys_old_readdir                 compat_sys_old_readdir
89      64      readdir                         sys_ni_syscall
89      spu     readdir                         sys_ni_syscall
90      common  mmap                            sys_mmap
91      common  munmap                          sys_munmap
92      common  truncate                        sys_truncate                    compat_sys_truncate
93      common  ftruncate                       sys_ftruncate                   compat_sys_ftruncate
94      common  fchmod                          sys_fchmod
95      common  fchown                          sys_fchown
96      common  getpriority                     sys_getpriority
97      common  setpriority                     sys_setpriority
98      common  profil                          sys_ni_syscall
99      nospu   statfs                          sys_statfs                      compat_sys_statfs
100     nospu   fstatfs                         sys_fstatfs                     compat_sys_fstatfs
101     common  ioperm                          sys_ni_syscall
102     common  socketcall                      sys_socketcall                  compat_sys_socketcall
103     common  syslog                          sys_syslog
104     common  setitimer                       sys_setitimer                   compat_sys_setitimer
105     common  getitimer                       sys_getitimer                   compat_sys_getitimer
106     common  stat                            sys_newstat                     compat_sys_newstat
107     common  lstat                           sys_newlstat                    compat_sys_newlstat
108     common  fstat                           sys_newfstat                    compat_sys_newfstat
109     32      olduname                        sys_uname
109     64      olduname                        sys_ni_syscall
109     spu     olduname                        sys_ni_syscall
110     common  iopl                            sys_ni_syscall
111     common  vhangup                         sys_vhangup
112     common  idle                            sys_ni_syscall
113     common  vm86                            sys_ni_syscall
114     common  wait4                           sys_wait4                       compat_sys_wait4
115     nospu   swapoff                         sys_swapoff
116     common  sysinfo                         sys_sysinfo                     compat_sys_sysinfo
117     nospu   ipc                             sys_ipc                         compat_sys_ipc
118     common  fsync                           sys_fsync
119     32      sigreturn                       sys_sigreturn                   compat_sys_sigreturn
119     64      sigreturn                       sys_ni_syscall
119     spu     sigreturn                       sys_ni_syscall
120     nospu   clone                           sys_clone
121     common  setdomainname                   sys_setdomainname
122     common  uname                           sys_newuname
123     common  modify_ldt                      sys_ni_syscall
124     32      adjtimex                        sys_adjtimex_time32
124     64      adjtimex                        sys_adjtimex
124     spu     adjtimex                        sys_adjtimex
125     common  mprotect                        sys_mprotect
126     32      sigprocmask                     sys_sigprocmask                 compat_sys_sigprocmask
126     64      sigprocmask                     sys_ni_syscall
126     spu     sigprocmask                     sys_ni_syscall
127     common  create_module                   sys_ni_syscall
128     nospu   init_module                     sys_init_module
129     nospu   delete_module                   sys_delete_module
130     common  get_kernel_syms                 sys_ni_syscall
131     nospu   quotactl                        sys_quotactl
132     common  getpgid                         sys_getpgid
133     common  fchdir                          sys_fchdir
134     common  bdflush                         sys_ni_syscall
135     common  sysfs                           sys_sysfs
136     32      personality                     sys_personality                 compat_sys_ppc64_personality
136     64      personality                     sys_ppc64_personality
136     spu     personality                     sys_ppc64_personality
137     common  afs_syscall                     sys_ni_syscall
138     common  setfsuid                        sys_setfsuid
139     common  setfsgid                        sys_setfsgid
140     common  _llseek                         sys_llseek
141     common  getdents                        sys_getdents                    compat_sys_getdents
142     common  _newselect                      sys_select                      compat_sys_select
143     common  flock                           sys_flock
144     common  msync                           sys_msync
145     common  readv                           sys_readv
146     common  writev                          sys_writev
147     common  getsid                          sys_getsid
148     common  fdatasync                       sys_fdatasync
149     nospu   _sysctl                         sys_ni_syscall
150     common  mlock                           sys_mlock
151     common  munlock                         sys_munlock
152     common  mlockall                        sys_mlockall
153     common  munlockall                      sys_munlockall
154     common  sched_setparam                  sys_sched_setparam
155     common  sched_getparam                  sys_sched_getparam
156     common  sched_setscheduler              sys_sched_setscheduler
157     common  sched_getscheduler              sys_sched_getscheduler
158     common  sched_yield                     sys_sched_yield
159     common  sched_get_priority_max          sys_sched_get_priority_max
160     common  sched_get_priority_min          sys_sched_get_priority_min
161     32      sched_rr_get_interval           sys_sched_rr_get_interval_time32
161     64      sched_rr_get_interval           sys_sched_rr_get_interval
161     spu     sched_rr_get_interval           sys_sched_rr_get_interval
162     32      nanosleep                       sys_nanosleep_time32
162     64      nanosleep                       sys_nanosleep
162     spu     nanosleep                       sys_nanosleep
163     common  mremap                          sys_mremap
164     common  setresuid                       sys_setresuid
165     common  getresuid                       sys_getresuid
166     common  query_module                    sys_ni_syscall
167     common  poll                            sys_poll
168     common  nfsservctl                      sys_ni_syscall
169     common  setresgid                       sys_setresgid
170     common  getresgid                       sys_getresgid
171     common  prctl                           sys_prctl
172     nospu   rt_sigreturn                    sys_rt_sigreturn                compat_sys_rt_sigreturn
173     nospu   rt_sigaction                    sys_rt_sigaction                compat_sys_rt_sigaction
174     nospu   rt_sigprocmask                  sys_rt_sigprocmask              compat_sys_rt_sigprocmask
175     nospu   rt_sigpending                   sys_rt_sigpending               compat_sys_rt_sigpending
176     32      rt_sigtimedwait                 sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
176     64      rt_sigtimedwait                 sys_rt_sigtimedwait
177     nospu   rt_sigqueueinfo                 sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
178     nospu   rt_sigsuspend                   sys_rt_sigsuspend               compat_sys_rt_sigsuspend
179     32      pread64                         sys_ppc_pread64                 compat_sys_ppc_pread64
179     64      pread64                         sys_pread64
179     spu     pread64                         sys_pread64
180     32      pwrite64                        sys_ppc_pwrite64                compat_sys_ppc_pwrite64
180     64      pwrite64                        sys_pwrite64
180     spu     pwrite64                        sys_pwrite64
181     common  chown                           sys_chown
182     common  getcwd                          sys_getcwd
183     common  capget                          sys_capget
184     common  capset                          sys_capset
185     nospu   sigaltstack                     sys_sigaltstack                 compat_sys_sigaltstack
186     32      sendfile                        sys_sendfile                    compat_sys_sendfile
186     64      sendfile                        sys_sendfile64
186     spu     sendfile                        sys_sendfile64
187     common  getpmsg                         sys_ni_syscall
188     common  putpmsg                         sys_ni_syscall
189     nospu   vfork                           sys_vfork
190     common  ugetrlimit                      sys_getrlimit                   compat_sys_getrlimit
191     32      readahead                       sys_ppc_readahead               compat_sys_ppc_readahead
191     64      readahead                       sys_readahead
191     spu     readahead                       sys_readahead
192     32      mmap2                           sys_mmap2                       compat_sys_mmap2
193     32      truncate64                      sys_ppc_truncate64              compat_sys_ppc_truncate64
194     32      ftruncate64                     sys_ppc_ftruncate64             compat_sys_ppc_ftruncate64
195     32      stat64                          sys_stat64
196     32      lstat64                         sys_lstat64
197     32      fstat64                         sys_fstat64
198     nospu   pciconfig_read                  sys_pciconfig_read
199     nospu   pciconfig_write                 sys_pciconfig_write
200     nospu   pciconfig_iobase                sys_pciconfig_iobase
201     common  multiplexer                     sys_ni_syscall
202     common  getdents64                      sys_getdents64
203     common  pivot_root                      sys_pivot_root
204     32      fcntl64                         sys_fcntl64                     compat_sys_fcntl64
205     common  madvise                         sys_madvise
206     common  mincore                         sys_mincore
207     common  gettid                          sys_gettid
208     common  tkill                           sys_tkill
209     common  setxattr                        sys_setxattr
210     common  lsetxattr                       sys_lsetxattr
211     common  fsetxattr                       sys_fsetxattr
212     common  getxattr                        sys_getxattr
213     common  lgetxattr                       sys_lgetxattr
214     common  fgetxattr                       sys_fgetxattr
215     common  listxattr                       sys_listxattr
216     common  llistxattr                      sys_llistxattr
217     common  flistxattr                      sys_flistxattr
218     common  removexattr                     sys_removexattr
219     common  lremovexattr                    sys_lremovexattr
220     common  fremovexattr                    sys_fremovexattr
221     32      futex                           sys_futex_time32
221     64      futex                           sys_futex
221     spu     futex                           sys_futex
222     common  sched_setaffinity               sys_sched_setaffinity           compat_sys_sched_setaffinity
223     common  sched_getaffinity               sys_sched_getaffinity           compat_sys_sched_getaffinity
225     common  tuxcall                         sys_ni_syscall
226     32      sendfile64                      sys_sendfile64                  compat_sys_sendfile64
227     common  io_setup                        sys_io_setup                    compat_sys_io_setup
228     common  io_destroy                      sys_io_destroy
229     32      io_getevents                    sys_io_getevents_time32
229     64      io_getevents                    sys_io_getevents
229     spu     io_getevents                    sys_io_getevents
230     common  io_submit                       sys_io_submit                   compat_sys_io_submit
231     common  io_cancel                       sys_io_cancel
232     nospu   set_tid_address                 sys_set_tid_address
233     32      fadvise64                       sys_ppc32_fadvise64             compat_sys_ppc32_fadvise64
233     64      fadvise64                       sys_fadvise64
233     spu     fadvise64                       sys_fadvise64
234     nospu   exit_group                      sys_exit_group
235     nospu   lookup_dcookie                  sys_ni_syscall
236     common  epoll_create                    sys_epoll_create
237     common  epoll_ctl                       sys_epoll_ctl
238     common  epoll_wait                      sys_epoll_wait
239     common  remap_file_pages                sys_remap_file_pages
240     common  timer_create                    sys_timer_create                compat_sys_timer_create
241     32      timer_settime                   sys_timer_settime32
241     64      timer_settime                   sys_timer_settime
241     spu     timer_settime                   sys_timer_settime
242     32      timer_gettime                   sys_timer_gettime32
242     64      timer_gettime                   sys_timer_gettime
242     spu     timer_gettime                   sys_timer_gettime
243     common  timer_getoverrun                sys_timer_getoverrun
244     common  timer_delete                    sys_timer_delete
245     32      clock_settime                   sys_clock_settime32
245     64      clock_settime                   sys_clock_settime
245     spu     clock_settime                   sys_clock_settime
246     32      clock_gettime                   sys_clock_gettime32
246     64      clock_gettime                   sys_clock_gettime
246     spu     clock_gettime                   sys_clock_gettime
247     32      clock_getres                    sys_clock_getres_time32
247     64      clock_getres                    sys_clock_getres
247     spu     clock_getres                    sys_clock_getres
248     32      clock_nanosleep                 sys_clock_nanosleep_time32
248     64      clock_nanosleep                 sys_clock_nanosleep
248     spu     clock_nanosleep                 sys_clock_nanosleep
249     nospu   swapcontext                     sys_swapcontext                 compat_sys_swapcontext
250     common  tgkill                          sys_tgkill
251     32      utimes                          sys_utimes_time32
251     64      utimes                          sys_utimes
251     spu     utimes                          sys_utimes
252     common  statfs64                        sys_statfs64                    compat_sys_statfs64
253     common  fstatfs64                       sys_fstatfs64                   compat_sys_fstatfs64
254     32      fadvise64_64                    sys_ppc_fadvise64_64
254     spu     fadvise64_64                    sys_ni_syscall
255     common  rtas                            sys_rtas
256     32      sys_debug_setcontext            sys_debug_setcontext            sys_ni_syscall
256     64      sys_debug_setcontext            sys_ni_syscall
256     spu     sys_debug_setcontext            sys_ni_syscall
258     nospu   migrate_pages                   sys_migrate_pages
259     nospu   mbind                           sys_mbind
260     nospu   get_mempolicy                   sys_get_mempolicy
261     nospu   set_mempolicy                   sys_set_mempolicy
262     nospu   mq_open                         sys_mq_open                     compat_sys_mq_open
263     nospu   mq_unlink                       sys_mq_unlink
264     32      mq_timedsend                    sys_mq_timedsend_time32
264     64      mq_timedsend                    sys_mq_timedsend
265     32      mq_timedreceive                 sys_mq_timedreceive_time32
265     64      mq_timedreceive                 sys_mq_timedreceive
266     nospu   mq_notify                       sys_mq_notify                   compat_sys_mq_notify
267     nospu   mq_getsetattr                   sys_mq_getsetattr               compat_sys_mq_getsetattr
268     nospu   kexec_load                      sys_kexec_load                  compat_sys_kexec_load
269     nospu   add_key                         sys_add_key
270     nospu   request_key                     sys_request_key
271     nospu   keyctl                          sys_keyctl                      compat_sys_keyctl
272     nospu   waitid                          sys_waitid                      compat_sys_waitid
273     nospu   ioprio_set                      sys_ioprio_set
274     nospu   ioprio_get                      sys_ioprio_get
275     nospu   inotify_init                    sys_inotify_init
276     nospu   inotify_add_watch               sys_inotify_add_watch
277     nospu   inotify_rm_watch                sys_inotify_rm_watch
278     nospu   spu_run                         sys_spu_run
279     nospu   spu_create                      sys_spu_create
280     32      pselect6                        sys_pselect6_time32             compat_sys_pselect6_time32
280     64      pselect6                        sys_pselect6
281     32      ppoll                           sys_ppoll_time32                compat_sys_ppoll_time32
281     64      ppoll                           sys_ppoll
282     common  unshare                         sys_unshare
283     common  splice                          sys_splice
284     common  tee                             sys_tee
285     common  vmsplice                        sys_vmsplice
286     common  openat                          sys_openat                      compat_sys_openat
287     common  mkdirat                         sys_mkdirat
288     common  mknodat                         sys_mknodat
289     common  fchownat                        sys_fchownat
290     32      futimesat                       sys_futimesat_time32
290     64      futimesat                       sys_futimesat
290     spu     utimesat                        sys_futimesat
291     32      fstatat64                       sys_fstatat64
291     64      newfstatat                      sys_newfstatat
291     spu     newfstatat                      sys_newfstatat
292     common  unlinkat                        sys_unlinkat
293     common  renameat                        sys_renameat
294     common  linkat                          sys_linkat
295     common  symlinkat                       sys_symlinkat
296     common  readlinkat                      sys_readlinkat
297     common  fchmodat                        sys_fchmodat
298     common  faccessat                       sys_faccessat
299     common  get_robust_list                 sys_get_robust_list             compat_sys_get_robust_list
300     common  set_robust_list                 sys_set_robust_list             compat_sys_set_robust_list
301     common  move_pages                      sys_move_pages
302     common  getcpu                          sys_getcpu
303     nospu   epoll_pwait                     sys_epoll_pwait                 compat_sys_epoll_pwait
304     32      utimensat                       sys_utimensat_time32
304     64      utimensat                       sys_utimensat
304     spu     utimensat                       sys_utimensat
305     common  signalfd                        sys_signalfd                    compat_sys_signalfd
306     common  timerfd_create                  sys_timerfd_create
307     common  eventfd                         sys_eventfd
308     32      sync_file_range2                sys_ppc_sync_file_range2        compat_sys_ppc_sync_file_range2
308     64      sync_file_range2                sys_sync_file_range2
308     spu     sync_file_range2                sys_sync_file_range2
309     32      fallocate                       sys_ppc_fallocate               compat_sys_fallocate
309     64      fallocate                       sys_fallocate
310     nospu   subpage_prot                    sys_subpage_prot
311     32      timerfd_settime                 sys_timerfd_settime32
311     64      timerfd_settime                 sys_timerfd_settime
311     spu     timerfd_settime                 sys_timerfd_settime
312     32      timerfd_gettime                 sys_timerfd_gettime32
312     64      timerfd_gettime                 sys_timerfd_gettime
312     spu     timerfd_gettime                 sys_timerfd_gettime
313     common  signalfd4                       sys_signalfd4                   compat_sys_signalfd4
314     common  eventfd2                        sys_eventfd2
315     common  epoll_create1                   sys_epoll_create1
316     common  dup3                            sys_dup3
317     common  pipe2                           sys_pipe2
318     nospu   inotify_init1                   sys_inotify_init1
319     common  perf_event_open                 sys_perf_event_open
320     common  preadv                          sys_preadv                      compat_sys_preadv
321     common  pwritev                         sys_pwritev                     compat_sys_pwritev
322     nospu   rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
323     nospu   fanotify_init                   sys_fanotify_init
324     nospu   fanotify_mark                   sys_fanotify_mark               compat_sys_fanotify_mark
325     common  prlimit64                       sys_prlimit64
326     common  socket                          sys_socket
327     common  bind                            sys_bind
328     common  connect                         sys_connect
329     common  listen                          sys_listen
330     common  accept                          sys_accept
331     common  getsockname                     sys_getsockname
332     common  getpeername                     sys_getpeername
333     common  socketpair                      sys_socketpair
334     common  send                            sys_send
335     common  sendto                          sys_sendto
336     common  recv                            sys_recv                        compat_sys_recv
337     common  recvfrom                        sys_recvfrom                    compat_sys_recvfrom
338     common  shutdown                        sys_shutdown
339     common  setsockopt                      sys_setsockopt                  sys_setsockopt
340     common  getsockopt                      sys_getsockopt                  sys_getsockopt
341     common  sendmsg                         sys_sendmsg                     compat_sys_sendmsg
342     common  recvmsg                         sys_recvmsg                     compat_sys_recvmsg
343     32      recvmmsg                        sys_recvmmsg_time32             compat_sys_recvmmsg_time32
343     64      recvmmsg                        sys_recvmmsg
343     spu     recvmmsg                        sys_recvmmsg
344     common  accept4                         sys_accept4
345     common  name_to_handle_at               sys_name_to_handle_at
346     common  open_by_handle_at               sys_open_by_handle_at           compat_sys_open_by_handle_at
347     32      clock_adjtime                   sys_clock_adjtime32
347     64      clock_adjtime                   sys_clock_adjtime
347     spu     clock_adjtime                   sys_clock_adjtime
348     common  syncfs                          sys_syncfs
349     common  sendmmsg                        sys_sendmmsg                    compat_sys_sendmmsg
350     common  setns                           sys_setns
351     nospu   process_vm_readv                sys_process_vm_readv
352     nospu   process_vm_writev               sys_process_vm_writev
353     nospu   finit_module                    sys_finit_module
354     nospu   kcmp                            sys_kcmp
355     common  sched_setattr                   sys_sched_setattr
356     common  sched_getattr                   sys_sched_getattr
357     common  renameat2                       sys_renameat2
358     common  seccomp                         sys_seccomp
359     common  getrandom                       sys_getrandom
360     common  memfd_create                    sys_memfd_create
361     common  bpf                             sys_bpf
362     nospu   execveat                        sys_execveat                    compat_sys_execveat
363     32      switch_endian                   sys_ni_syscall
363     64      switch_endian                   sys_switch_endian
363     spu     switch_endian                   sys_ni_syscall
364     common  userfaultfd                     sys_userfaultfd
365     common  membarrier                      sys_membarrier
378     nospu   mlock2                          sys_mlock2
379     nospu   copy_file_range                 sys_copy_file_range
380     common  preadv2                         sys_preadv2                     compat_sys_preadv2
381     common  pwritev2                        sys_pwritev2                    compat_sys_pwritev2
382     nospu   kexec_file_load                 sys_kexec_file_load
383     nospu   statx                           sys_statx
384     nospu   pkey_alloc                      sys_pkey_alloc
385     nospu   pkey_free                       sys_pkey_free
386     nospu   pkey_mprotect                   sys_pkey_mprotect
387     nospu   rseq                            sys_rseq
388     32      io_pgetevents                   sys_io_pgetevents_time32        compat_sys_io_pgetevents
388     64      io_pgetevents                   sys_io_pgetevents
392     64      semtimedop                      sys_semtimedop
393     common  semget                          sys_semget
394     common  semctl                          sys_semctl                      compat_sys_semctl
395     common  shmget                          sys_shmget
396     common  shmctl                          sys_shmctl                      compat_sys_shmctl
397     common  shmat                           sys_shmat                       compat_sys_shmat
398     common  shmdt                           sys_shmdt
399     common  msgget                          sys_msgget
400     common  msgsnd                          sys_msgsnd                      compat_sys_msgsnd
401     common  msgrcv                          sys_msgrcv                      compat_sys_msgrcv
402     common  msgctl                          sys_msgctl                      compat_sys_msgctl
403     32      clock_gettime64                 sys_clock_gettime               sys_clock_gettime
404     32      clock_settime64                 sys_clock_settime               sys_clock_settime
405     32      clock_adjtime64                 sys_clock_adjtime               sys_clock_adjtime
406     32      clock_getres_time64             sys_clock_getres                sys_clock_getres
407     32      clock_nanosleep_time64          sys_clock_nanosleep             sys_clock_nanosleep
408     32      timer_gettime64                 sys_timer_gettime               sys_timer_gettime
409     32      timer_settime64                 sys_timer_settime               sys_timer_settime
410     32      timerfd_gettime64               sys_timerfd_gettime             sys_timerfd_gettime
411     32      timerfd_settime64               sys_timerfd_settime             sys_timerfd_settime
412     32      utimensat_time64                sys_utimensat                   sys_utimensat
413     32      pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     32      ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     32      io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     32      recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     32      mq_timedsend_time64             sys_mq_timedsend                sys_mq_timedsend
419     32      mq_timedreceive_time64          sys_mq_timedreceive             sys_mq_timedreceive
420     32      semtimedop_time64               sys_semtimedop                  sys_semtimedop
421     32      rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     32      futex_time64                    sys_futex                       sys_futex
423     32      sched_rr_get_interval_time64    sys_sched_rr_get_interval       sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     nospu   clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     nospu   set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_ni_syscall
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     nospu   rseq_slice_yield                sys_rseq_slice_yield
"""


# SPARC
# - arch/sparc/kernel/syscalls/syscall.tbl
sparc_syscall_tbl = """
0       common  restart_syscall         sys_restart_syscall
1       32      exit                    sys_exit                        sparc_exit
1       64      exit                    sparc_exit
2       common  fork                    sys_fork
3       common  read                    sys_read
4       common  write                   sys_write
5       common  open                    sys_open                        compat_sys_open
6       common  close                   sys_close
7       common  wait4                   sys_wait4                       compat_sys_wait4
8       common  creat                   sys_creat
9       common  link                    sys_link
10      common  unlink                  sys_unlink
11      32      execv                   sunos_execv
11      64      execv                   sys_nis_syscall
12      common  chdir                   sys_chdir
13      32      chown                   sys_chown16
13      64      chown                   sys_chown
14      common  mknod                   sys_mknod
15      common  chmod                   sys_chmod
16      32      lchown                  sys_lchown16
16      64      lchown                  sys_lchown
17      common  brk                     sys_brk
18      common  perfctr                 sys_nis_syscall
19      common  lseek                   sys_lseek                       compat_sys_lseek
20      common  getpid                  sys_getpid
21      common  capget                  sys_capget
22      common  capset                  sys_capset
23      32      setuid                  sys_setuid16
23      64      setuid                  sys_setuid
24      32      getuid                  sys_getuid16
24      64      getuid                  sys_getuid
25      common  vmsplice                sys_vmsplice
26      common  ptrace                  sys_ptrace                      compat_sys_ptrace
27      common  alarm                   sys_alarm
28      common  sigaltstack             sys_sigaltstack                 compat_sys_sigaltstack
29      32      pause                   sys_pause
29      64      pause                   sys_nis_syscall
30      32      utime                   sys_utime32
30      64      utime                   sys_utime
31      32      lchown32                sys_lchown
32      32      fchown32                sys_fchown
33      common  access                  sys_access
34      common  nice                    sys_nice
35      32      chown32                 sys_chown
36      common  sync                    sys_sync
37      common  kill                    sys_kill
38      common  stat                    sys_newstat                     compat_sys_newstat
39      32      sendfile                sys_sendfile                    compat_sys_sendfile
39      64      sendfile                sys_sendfile64
40      common  lstat                   sys_newlstat                    compat_sys_newlstat
41      common  dup                     sys_dup
42      common  pipe                    sys_sparc_pipe
43      common  times                   sys_times                       compat_sys_times
44      32      getuid32                sys_getuid
45      common  umount2                 sys_umount
46      32      setgid                  sys_setgid16
46      64      setgid                  sys_setgid
47      32      getgid                  sys_getgid16
47      64      getgid                  sys_getgid
48      common  signal                  sys_signal
49      32      geteuid                 sys_geteuid16
49      64      geteuid                 sys_geteuid
50      32      getegid                 sys_getegid16
50      64      getegid                 sys_getegid
51      common  acct                    sys_acct
52      64      memory_ordering         sys_memory_ordering
53      32      getgid32                sys_getgid
54      common  ioctl                   sys_ioctl                       compat_sys_ioctl
55      common  reboot                  sys_reboot
56      32      mmap2                   sys_mmap2                       sys32_mmap2
57      common  symlink                 sys_symlink
58      common  readlink                sys_readlink
59      32      execve                  sys_execve                      sys32_execve
59      64      execve                  sys64_execve
60      common  umask                   sys_umask
61      common  chroot                  sys_chroot
62      common  fstat                   sys_newfstat                    compat_sys_newfstat
63      common  fstat64                 sys_fstat64                     compat_sys_fstat64
64      common  getpagesize             sys_getpagesize
65      common  msync                   sys_msync
66      common  vfork                   sys_vfork
67      common  pread64                 sys_pread64                     compat_sys_pread64
68      common  pwrite64                sys_pwrite64                    compat_sys_pwrite64
69      32      geteuid32               sys_geteuid
70      32      getegid32               sys_getegid
71      common  mmap                    sys_mmap
72      32      setreuid32              sys_setreuid
73      32      munmap                  sys_munmap
73      64      munmap                  sys_64_munmap
74      common  mprotect                sys_mprotect
75      common  madvise                 sys_madvise
76      common  vhangup                 sys_vhangup
77      32      truncate64              sys_truncate64                  compat_sys_truncate64
78      common  mincore                 sys_mincore
79      32      getgroups               sys_getgroups16
79      64      getgroups               sys_getgroups
80      32      setgroups               sys_setgroups16
80      64      setgroups               sys_setgroups
81      common  getpgrp                 sys_getpgrp
82      32      setgroups32             sys_setgroups
83      common  setitimer               sys_setitimer                   compat_sys_setitimer
84      32      ftruncate64             sys_ftruncate64                 compat_sys_ftruncate64
85      common  swapon                  sys_swapon
86      common  getitimer               sys_getitimer                   compat_sys_getitimer
87      32      setuid32                sys_setuid
88      common  sethostname             sys_sethostname
89      32      setgid32                sys_setgid
90      common  dup2                    sys_dup2
91      32      setfsuid32              sys_setfsuid
92      common  fcntl                   sys_fcntl                       compat_sys_fcntl
93      common  select                  sys_select                      compat_sys_select
94      32      setfsgid32              sys_setfsgid
95      common  fsync                   sys_fsync
96      common  setpriority             sys_setpriority
97      common  socket                  sys_socket
98      common  connect                 sys_connect
99      common  accept                  sys_accept
100     common  getpriority             sys_getpriority
101     common  rt_sigreturn            sys_rt_sigreturn                sys32_rt_sigreturn
102     common  rt_sigaction            sys_rt_sigaction                compat_sys_rt_sigaction
103     common  rt_sigprocmask          sys_rt_sigprocmask              compat_sys_rt_sigprocmask
104     common  rt_sigpending           sys_rt_sigpending               compat_sys_rt_sigpending
105     32      rt_sigtimedwait         sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
105     64      rt_sigtimedwait         sys_rt_sigtimedwait
106     common  rt_sigqueueinfo         sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
107     common  rt_sigsuspend           sys_rt_sigsuspend               compat_sys_rt_sigsuspend
108     32      setresuid32             sys_setresuid
108     64      setresuid               sys_setresuid
109     32      getresuid32             sys_getresuid
109     64      getresuid               sys_getresuid
110     32      setresgid32             sys_setresgid
110     64      setresgid               sys_setresgid
111     32      getresgid32             sys_getresgid
111     64      getresgid               sys_getresgid
112     32      setregid32              sys_setregid
113     common  recvmsg                 sys_recvmsg                     compat_sys_recvmsg
114     common  sendmsg                 sys_sendmsg                     compat_sys_sendmsg
115     32      getgroups32             sys_getgroups
116     common  gettimeofday            sys_gettimeofday                compat_sys_gettimeofday
117     common  getrusage               sys_getrusage                   compat_sys_getrusage
118     common  getsockopt              sys_getsockopt                  sys_getsockopt
119     common  getcwd                  sys_getcwd
120     common  readv                   sys_readv
121     common  writev                  sys_writev
122     common  settimeofday            sys_settimeofday                compat_sys_settimeofday
123     32      fchown                  sys_fchown16
123     64      fchown                  sys_fchown
124     common  fchmod                  sys_fchmod
125     common  recvfrom                sys_recvfrom                    compat_sys_recvfrom
126     32      setreuid                sys_setreuid16
126     64      setreuid                sys_setreuid
127     32      setregid                sys_setregid16
127     64      setregid                sys_setregid
128     common  rename                  sys_rename
129     common  truncate                sys_truncate                    compat_sys_truncate
130     common  ftruncate               sys_ftruncate                   compat_sys_ftruncate
131     common  flock                   sys_flock
132     common  lstat64                 sys_lstat64                     compat_sys_lstat64
133     common  sendto                  sys_sendto
134     common  shutdown                sys_shutdown
135     common  socketpair              sys_socketpair
136     common  mkdir                   sys_mkdir
137     common  rmdir                   sys_rmdir
138     32      utimes                  sys_utimes_time32
138     64      utimes                  sys_utimes
139     common  stat64                  sys_stat64                      compat_sys_stat64
140     common  sendfile64              sys_sendfile64
141     common  getpeername             sys_getpeername
142     32      futex                   sys_futex_time32
142     64      futex                   sys_futex
143     common  gettid                  sys_gettid
144     common  getrlimit               sys_getrlimit                   compat_sys_getrlimit
145     common  setrlimit               sys_setrlimit                   compat_sys_setrlimit
146     common  pivot_root              sys_pivot_root
147     common  prctl                   sys_prctl
148     common  pciconfig_read          sys_pciconfig_read
149     common  pciconfig_write         sys_pciconfig_write
150     common  getsockname             sys_getsockname
151     common  inotify_init            sys_inotify_init
152     common  inotify_add_watch       sys_inotify_add_watch
153     common  poll                    sys_poll
154     common  getdents64              sys_getdents64
155     32      fcntl64                 sys_fcntl64                     compat_sys_fcntl64
156     common  inotify_rm_watch        sys_inotify_rm_watch
157     common  statfs                  sys_statfs                      compat_sys_statfs
158     common  fstatfs                 sys_fstatfs                     compat_sys_fstatfs
159     common  umount                  sys_oldumount
160     common  sched_set_affinity      sys_sched_setaffinity           compat_sys_sched_setaffinity
161     common  sched_get_affinity      sys_sched_getaffinity           compat_sys_sched_getaffinity
162     common  getdomainname           sys_getdomainname
163     common  setdomainname           sys_setdomainname
164     64      utrap_install           sys_utrap_install
165     common  quotactl                sys_quotactl
166     common  set_tid_address         sys_set_tid_address
167     common  mount                   sys_mount
168     common  ustat                   sys_ustat                       compat_sys_ustat
169     common  setxattr                sys_setxattr
170     common  lsetxattr               sys_lsetxattr
171     common  fsetxattr               sys_fsetxattr
172     common  getxattr                sys_getxattr
173     common  lgetxattr               sys_lgetxattr
174     common  getdents                sys_getdents                    compat_sys_getdents
175     common  setsid                  sys_setsid
176     common  fchdir                  sys_fchdir
177     common  fgetxattr               sys_fgetxattr
178     common  listxattr               sys_listxattr
179     common  llistxattr              sys_llistxattr
180     common  flistxattr              sys_flistxattr
181     common  removexattr             sys_removexattr
182     common  lremovexattr            sys_lremovexattr
183     32      sigpending              sys_sigpending                  compat_sys_sigpending
183     64      sigpending              sys_nis_syscall
184     common  query_module            sys_ni_syscall
185     common  setpgid                 sys_setpgid
186     common  fremovexattr            sys_fremovexattr
187     common  tkill                   sys_tkill
188     32      exit_group              sys_exit_group                  sparc_exit_group
188     64      exit_group              sparc_exit_group
189     common  uname                   sys_newuname
190     common  init_module             sys_init_module
191     32      personality             sys_personality                 sys_sparc64_personality
191     64      personality             sys_sparc64_personality
192     32      remap_file_pages        sys_sparc_remap_file_pages      sys_remap_file_pages
192     64      remap_file_pages        sys_remap_file_pages
193     common  epoll_create            sys_epoll_create
194     common  epoll_ctl               sys_epoll_ctl
195     common  epoll_wait              sys_epoll_wait
196     common  ioprio_set              sys_ioprio_set
197     common  getppid                 sys_getppid
198     32      sigaction               sys_sparc_sigaction             compat_sys_sparc_sigaction
198     64      sigaction               sys_nis_syscall
199     common  sgetmask                sys_sgetmask
200     common  ssetmask                sys_ssetmask
201     32      sigsuspend              sys_sigsuspend
201     64      sigsuspend              sys_nis_syscall
202     common  oldlstat                sys_newlstat                    compat_sys_newlstat
203     common  uselib                  sys_uselib
204     32      readdir                 sys_old_readdir                 compat_sys_old_readdir
204     64      readdir                 sys_nis_syscall
205     common  readahead               sys_readahead                   compat_sys_readahead
206     common  socketcall              sys_socketcall                  compat_sys_socketcall
207     common  syslog                  sys_syslog
208     common  lookup_dcookie          sys_ni_syscall
209     common  fadvise64               sys_fadvise64                   compat_sys_fadvise64
210     common  fadvise64_64            sys_fadvise64_64                compat_sys_fadvise64_64
211     common  tgkill                  sys_tgkill
212     common  waitpid                 sys_waitpid
213     common  swapoff                 sys_swapoff
214     common  sysinfo                 sys_sysinfo                     compat_sys_sysinfo
215     32      ipc                     sys_ipc                         compat_sys_ipc
215     64      ipc                     sys_sparc_ipc
216     32      sigreturn               sys_sigreturn                   sys32_sigreturn
216     64      sigreturn               sys_nis_syscall
217     common  clone                   sys_clone
218     common  ioprio_get              sys_ioprio_get
219     32      adjtimex                sys_adjtimex_time32
219     64      adjtimex                sys_sparc_adjtimex
220     32      sigprocmask             sys_sigprocmask                 compat_sys_sigprocmask
220     64      sigprocmask             sys_nis_syscall
221     common  create_module           sys_ni_syscall
222     common  delete_module           sys_delete_module
223     common  get_kernel_syms         sys_ni_syscall
224     common  getpgid                 sys_getpgid
225     common  bdflush                 sys_ni_syscall
226     common  sysfs                   sys_sysfs
227     common  afs_syscall             sys_nis_syscall
228     common  setfsuid                sys_setfsuid16
229     common  setfsgid                sys_setfsgid16
230     common  _newselect              sys_select                      compat_sys_select
231     32      time                    sys_time32
232     common  splice                  sys_splice
233     32      stime                   sys_stime32
233     64      stime                   sys_stime
234     common  statfs64                sys_statfs64                    compat_sys_statfs64
235     common  fstatfs64               sys_fstatfs64                   compat_sys_fstatfs64
236     common  _llseek                 sys_llseek
237     common  mlock                   sys_mlock
238     common  munlock                 sys_munlock
239     common  mlockall                sys_mlockall
240     common  munlockall              sys_munlockall
241     common  sched_setparam          sys_sched_setparam
242     common  sched_getparam          sys_sched_getparam
243     common  sched_setscheduler      sys_sched_setscheduler
244     common  sched_getscheduler      sys_sched_getscheduler
245     common  sched_yield             sys_sched_yield
246     common  sched_get_priority_max  sys_sched_get_priority_max
247     common  sched_get_priority_min  sys_sched_get_priority_min
248     32      sched_rr_get_interval   sys_sched_rr_get_interval_time32
248     64      sched_rr_get_interval   sys_sched_rr_get_interval
249     32      nanosleep               sys_nanosleep_time32
249     64      nanosleep               sys_nanosleep
250     32      mremap                  sys_mremap
250     64      mremap                  sys_64_mremap
251     common  _sysctl                 sys_ni_syscall
252     common  getsid                  sys_getsid
253     common  fdatasync               sys_fdatasync
254     32      nfsservctl              sys_ni_syscall                  sys_nis_syscall
254     64      nfsservctl              sys_nis_syscall
255     common  sync_file_range         sys_sync_file_range             compat_sys_sync_file_range
256     32      clock_settime           sys_clock_settime32
256     64      clock_settime           sys_clock_settime
257     32      clock_gettime           sys_clock_gettime32
257     64      clock_gettime           sys_clock_gettime
258     32      clock_getres            sys_clock_getres_time32
258     64      clock_getres            sys_clock_getres
259     32      clock_nanosleep         sys_clock_nanosleep_time32
259     64      clock_nanosleep         sys_clock_nanosleep
260     common  sched_getaffinity       sys_sched_getaffinity           compat_sys_sched_getaffinity
261     common  sched_setaffinity       sys_sched_setaffinity           compat_sys_sched_setaffinity
262     32      timer_settime           sys_timer_settime32
262     64      timer_settime           sys_timer_settime
263     32      timer_gettime           sys_timer_gettime32
263     64      timer_gettime           sys_timer_gettime
264     common  timer_getoverrun        sys_timer_getoverrun
265     common  timer_delete            sys_timer_delete
266     common  timer_create            sys_timer_create                compat_sys_timer_create
267     common  vserver                 sys_nis_syscall
268     common  io_setup                sys_io_setup                    compat_sys_io_setup
269     common  io_destroy              sys_io_destroy
270     common  io_submit               sys_io_submit                   compat_sys_io_submit
271     common  io_cancel               sys_io_cancel
272     32      io_getevents            sys_io_getevents_time32
272     64      io_getevents            sys_io_getevents
273     common  mq_open                 sys_mq_open                     compat_sys_mq_open
274     common  mq_unlink               sys_mq_unlink
275     32      mq_timedsend            sys_mq_timedsend_time32
275     64      mq_timedsend            sys_mq_timedsend
276     32      mq_timedreceive         sys_mq_timedreceive_time32
276     64      mq_timedreceive         sys_mq_timedreceive
277     common  mq_notify               sys_mq_notify                   compat_sys_mq_notify
278     common  mq_getsetattr           sys_mq_getsetattr               compat_sys_mq_getsetattr
279     common  waitid                  sys_waitid                      compat_sys_waitid
280     common  tee                     sys_tee
281     common  add_key                 sys_add_key
282     common  request_key             sys_request_key
283     common  keyctl                  sys_keyctl                      compat_sys_keyctl
284     common  openat                  sys_openat                      compat_sys_openat
285     common  mkdirat                 sys_mkdirat
286     common  mknodat                 sys_mknodat
287     common  fchownat                sys_fchownat
288     32      futimesat               sys_futimesat_time32
288     64      futimesat               sys_futimesat
289     common  fstatat64               sys_fstatat64                   compat_sys_fstatat64
290     common  unlinkat                sys_unlinkat
291     common  renameat                sys_renameat
292     common  linkat                  sys_linkat
293     common  symlinkat               sys_symlinkat
294     common  readlinkat              sys_readlinkat
295     common  fchmodat                sys_fchmodat
296     common  faccessat               sys_faccessat
297     32      pselect6                sys_pselect6_time32             compat_sys_pselect6_time32
297     64      pselect6                sys_pselect6
298     32      ppoll                   sys_ppoll_time32                compat_sys_ppoll_time32
298     64      ppoll                   sys_ppoll
299     common  unshare                 sys_unshare
300     common  set_robust_list         sys_set_robust_list             compat_sys_set_robust_list
301     common  get_robust_list         sys_get_robust_list             compat_sys_get_robust_list
302     common  migrate_pages           sys_migrate_pages
303     common  mbind                   sys_mbind
304     common  get_mempolicy           sys_get_mempolicy
305     common  set_mempolicy           sys_set_mempolicy
306     common  kexec_load              sys_kexec_load                  compat_sys_kexec_load
307     common  move_pages              sys_move_pages
308     common  getcpu                  sys_getcpu
309     common  epoll_pwait             sys_epoll_pwait                 compat_sys_epoll_pwait
310     32      utimensat               sys_utimensat_time32
310     64      utimensat               sys_utimensat
311     common  signalfd                sys_signalfd                    compat_sys_signalfd
312     common  timerfd_create          sys_timerfd_create
313     common  eventfd                 sys_eventfd
314     common  fallocate               sys_fallocate                   compat_sys_fallocate
315     32      timerfd_settime         sys_timerfd_settime32
315     64      timerfd_settime         sys_timerfd_settime
316     32      timerfd_gettime         sys_timerfd_gettime32
316     64      timerfd_gettime         sys_timerfd_gettime
317     common  signalfd4               sys_signalfd4                   compat_sys_signalfd4
318     common  eventfd2                sys_eventfd2
319     common  epoll_create1           sys_epoll_create1
320     common  dup3                    sys_dup3
321     common  pipe2                   sys_pipe2
322     common  inotify_init1           sys_inotify_init1
323     common  accept4                 sys_accept4
324     common  preadv                  sys_preadv                      compat_sys_preadv
325     common  pwritev                 sys_pwritev                     compat_sys_pwritev
326     common  rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
327     common  perf_event_open         sys_perf_event_open
328     32      recvmmsg                sys_recvmmsg_time32             compat_sys_recvmmsg_time32
328     64      recvmmsg                sys_recvmmsg
329     common  fanotify_init           sys_fanotify_init
330     common  fanotify_mark           sys_fanotify_mark               compat_sys_fanotify_mark
331     common  prlimit64               sys_prlimit64
332     common  name_to_handle_at       sys_name_to_handle_at
333     common  open_by_handle_at       sys_open_by_handle_at           compat_sys_open_by_handle_at
334     32      clock_adjtime           sys_clock_adjtime32
334     64      clock_adjtime           sys_sparc_clock_adjtime
335     common  syncfs                  sys_syncfs
336     common  sendmmsg                sys_sendmmsg                    compat_sys_sendmmsg
337     common  setns                   sys_setns
338     common  process_vm_readv        sys_process_vm_readv
339     common  process_vm_writev       sys_process_vm_writev
340     32      kern_features           sys_ni_syscall                  sys_kern_features
340     64      kern_features           sys_kern_features
341     common  kcmp                    sys_kcmp
342     common  finit_module            sys_finit_module
343     common  sched_setattr           sys_sched_setattr
344     common  sched_getattr           sys_sched_getattr
345     common  renameat2               sys_renameat2
346     common  seccomp                 sys_seccomp
347     common  getrandom               sys_getrandom
348     common  memfd_create            sys_memfd_create
349     common  bpf                     sys_bpf
350     32      execveat                sys_execveat                    sys32_execveat
350     64      execveat                sys64_execveat
351     common  membarrier              sys_membarrier
352     common  userfaultfd             sys_userfaultfd
353     common  bind                    sys_bind
354     common  listen                  sys_listen
355     common  setsockopt              sys_setsockopt                  sys_setsockopt
356     common  mlock2                  sys_mlock2
357     common  copy_file_range         sys_copy_file_range
358     common  preadv2                 sys_preadv2                     compat_sys_preadv2
359     common  pwritev2                sys_pwritev2                    compat_sys_pwritev2
360     common  statx                   sys_statx
361     32      io_pgetevents           sys_io_pgetevents_time32        compat_sys_io_pgetevents
361     64      io_pgetevents           sys_io_pgetevents
362     common  pkey_mprotect           sys_pkey_mprotect
363     common  pkey_alloc              sys_pkey_alloc
364     common  pkey_free               sys_pkey_free
365     common  rseq                    sys_rseq
392     64      semtimedop                      sys_semtimedop
393     common  semget                  sys_semget
394     common  semctl                  sys_semctl                      compat_sys_semctl
395     common  shmget                  sys_shmget
396     common  shmctl                  sys_shmctl                      compat_sys_shmctl
397     common  shmat                   sys_shmat                       compat_sys_shmat
398     common  shmdt                   sys_shmdt
399     common  msgget                  sys_msgget
400     common  msgsnd                  sys_msgsnd                      compat_sys_msgsnd
401     common  msgrcv                  sys_msgrcv                      compat_sys_msgrcv
402     common  msgctl                  sys_msgctl                      compat_sys_msgctl
403     32      clock_gettime64                 sys_clock_gettime               sys_clock_gettime
404     32      clock_settime64                 sys_clock_settime               sys_clock_settime
405     32      clock_adjtime64                 sys_clock_adjtime               sys_clock_adjtime
406     32      clock_getres_time64             sys_clock_getres                sys_clock_getres
407     32      clock_nanosleep_time64          sys_clock_nanosleep             sys_clock_nanosleep
408     32      timer_gettime64                 sys_timer_gettime               sys_timer_gettime
409     32      timer_settime64                 sys_timer_settime               sys_timer_settime
410     32      timerfd_gettime64               sys_timerfd_gettime             sys_timerfd_gettime
411     32      timerfd_settime64               sys_timerfd_settime             sys_timerfd_settime
412     32      utimensat_time64                sys_utimensat                   sys_utimensat
413     32      pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     32      ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     32      io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     32      recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     32      mq_timedsend_time64             sys_mq_timedsend                sys_mq_timedsend
419     32      mq_timedreceive_time64          sys_mq_timedreceive             sys_mq_timedreceive
420     32      semtimedop_time64               sys_semtimedop                  sys_semtimedop
421     32      rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     32      futex_time64                    sys_futex                       sys_futex
423     32      sched_rr_get_interval_time64    sys_sched_rr_get_interval       sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          __sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                 sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# RISCV64
riscv64_syscall_tbl = arm64_syscall_tbl


# RISCV32
riscv32_syscall_tbl = arm64_syscall_tbl


# S390X
# - arch/s390/kernel/syscalls/syscall.tbl
s390x_syscall_tbl = """
1       common  exit                            sys_exit
2       common  fork                            sys_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  open                            sys_open
6       common  close                           sys_close
7       common  restart_syscall                 sys_restart_syscall
8       common  creat                           sys_creat
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      common  execve                          sys_execve
12      common  chdir                           sys_chdir
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
19      common  lseek                           sys_lseek
20      common  getpid                          sys_getpid
21      common  mount                           sys_mount
22      common  umount                          sys_oldumount
26      common  ptrace                          sys_ptrace
27      common  alarm                           sys_alarm
29      common  pause                           sys_pause
30      common  utime                           sys_utime
33      common  access                          sys_access
34      common  nice                            sys_nice
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  rename                          sys_rename
39      common  mkdir                           sys_mkdir
40      common  rmdir                           sys_rmdir
41      common  dup                             sys_dup
42      common  pipe                            sys_pipe
43      common  times                           sys_times
45      common  brk                             sys_brk
48      common  signal                          sys_signal
51      common  acct                            sys_acct
52      common  umount2                         sys_umount
54      common  ioctl                           sys_ioctl
55      common  fcntl                           sys_fcntl
57      common  setpgid                         sys_setpgid
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      common  ustat                           sys_ustat
63      common  dup2                            sys_dup2
64      common  getppid                         sys_getppid
65      common  getpgrp                         sys_getpgrp
66      common  setsid                          sys_setsid
67      common  sigaction                       sys_sigaction
72      common  sigsuspend                      sys_sigsuspend
73      common  sigpending                      sys_sigpending
74      common  sethostname                     sys_sethostname
75      common  setrlimit                       sys_setrlimit
77      common  getrusage                       sys_getrusage
78      common  gettimeofday                    sys_gettimeofday
79      common  settimeofday                    sys_settimeofday
83      common  symlink                         sys_symlink
85      common  readlink                        sys_readlink
86      common  uselib                          sys_uselib
87      common  swapon                          sys_swapon
88      common  reboot                          sys_reboot
89      common  readdir                         sys_ni_syscall
90      common  mmap                            sys_old_mmap
91      common  munmap                          sys_munmap
92      common  truncate                        sys_truncate
93      common  ftruncate                       sys_ftruncate
94      common  fchmod                          sys_fchmod
96      common  getpriority                     sys_getpriority
97      common  setpriority                     sys_setpriority
99      common  statfs                          sys_statfs
100     common  fstatfs                         sys_fstatfs
102     common  socketcall                      sys_socketcall
103     common  syslog                          sys_syslog
104     common  setitimer                       sys_setitimer
105     common  getitimer                       sys_getitimer
106     common  stat                            sys_newstat
107     common  lstat                           sys_newlstat
108     common  fstat                           sys_newfstat
110     common  lookup_dcookie                  sys_ni_syscall
111     common  vhangup                         sys_vhangup
112     common  idle                            sys_ni_syscall
114     common  wait4                           sys_wait4
115     common  swapoff                         sys_swapoff
116     common  sysinfo                         sys_sysinfo
117     common  ipc                             sys_s390_ipc
118     common  fsync                           sys_fsync
119     common  sigreturn                       sys_sigreturn
120     common  clone                           sys_clone
121     common  setdomainname                   sys_setdomainname
122     common  uname                           sys_newuname
124     common  adjtimex                        sys_adjtimex
125     common  mprotect                        sys_mprotect
126     common  sigprocmask                     sys_sigprocmask
127     common  create_module                   sys_ni_syscall
128     common  init_module                     sys_init_module
129     common  delete_module                   sys_delete_module
130     common  get_kernel_syms                 sys_ni_syscall
131     common  quotactl                        sys_quotactl
132     common  getpgid                         sys_getpgid
133     common  fchdir                          sys_fchdir
134     common  bdflush                         sys_ni_syscall
135     common  sysfs                           sys_sysfs
136     common  personality                     sys_s390_personality
137     common  afs_syscall                     sys_ni_syscall
141     common  getdents                        sys_getdents
142     common  select                          sys_select
143     common  flock                           sys_flock
144     common  msync                           sys_msync
145     common  readv                           sys_readv
146     common  writev                          sys_writev
147     common  getsid                          sys_getsid
148     common  fdatasync                       sys_fdatasync
149     common  _sysctl                         sys_ni_syscall
150     common  mlock                           sys_mlock
151     common  munlock                         sys_munlock
152     common  mlockall                        sys_mlockall
153     common  munlockall                      sys_munlockall
154     common  sched_setparam                  sys_sched_setparam
155     common  sched_getparam                  sys_sched_getparam
156     common  sched_setscheduler              sys_sched_setscheduler
157     common  sched_getscheduler              sys_sched_getscheduler
158     common  sched_yield                     sys_sched_yield
159     common  sched_get_priority_max          sys_sched_get_priority_max
160     common  sched_get_priority_min          sys_sched_get_priority_min
161     common  sched_rr_get_interval           sys_sched_rr_get_interval
162     common  nanosleep                       sys_nanosleep
163     common  mremap                          sys_mremap
167     common  query_module                    sys_ni_syscall
168     common  poll                            sys_poll
169     common  nfsservctl                      sys_ni_syscall
172     common  prctl                           sys_prctl
173     common  rt_sigreturn                    sys_rt_sigreturn
174     common  rt_sigaction                    sys_rt_sigaction
175     common  rt_sigprocmask                  sys_rt_sigprocmask
176     common  rt_sigpending                   sys_rt_sigpending
177     common  rt_sigtimedwait                 sys_rt_sigtimedwait
178     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
179     common  rt_sigsuspend                   sys_rt_sigsuspend
180     common  pread64                         sys_pread64
181     common  pwrite64                        sys_pwrite64
183     common  getcwd                          sys_getcwd
184     common  capget                          sys_capget
185     common  capset                          sys_capset
186     common  sigaltstack                     sys_sigaltstack
187     common  sendfile                        sys_sendfile64
188     common  getpmsg                         sys_ni_syscall
189     common  putpmsg                         sys_ni_syscall
190     common  vfork                           sys_vfork
191     common  getrlimit                       sys_getrlimit
198     common  lchown                          sys_lchown
199     common  getuid                          sys_getuid
200     common  getgid                          sys_getgid
201     common  geteuid                         sys_geteuid
202     common  getegid                         sys_getegid
203     common  setreuid                        sys_setreuid
204     common  setregid                        sys_setregid
205     common  getgroups                       sys_getgroups
206     common  setgroups                       sys_setgroups
207     common  fchown                          sys_fchown
208     common  setresuid                       sys_setresuid
209     common  getresuid                       sys_getresuid
210     common  setresgid                       sys_setresgid
211     common  getresgid                       sys_getresgid
212     common  chown                           sys_chown
213     common  setuid                          sys_setuid
214     common  setgid                          sys_setgid
215     common  setfsuid                        sys_setfsuid
216     common  setfsgid                        sys_setfsgid
217     common  pivot_root                      sys_pivot_root
218     common  mincore                         sys_mincore
219     common  madvise                         sys_madvise
220     common  getdents64                      sys_getdents64
222     common  readahead                       sys_readahead
224     common  setxattr                        sys_setxattr
225     common  lsetxattr                       sys_lsetxattr
226     common  fsetxattr                       sys_fsetxattr
227     common  getxattr                        sys_getxattr
228     common  lgetxattr                       sys_lgetxattr
229     common  fgetxattr                       sys_fgetxattr
230     common  listxattr                       sys_listxattr
231     common  llistxattr                      sys_llistxattr
232     common  flistxattr                      sys_flistxattr
233     common  removexattr                     sys_removexattr
234     common  lremovexattr                    sys_lremovexattr
235     common  fremovexattr                    sys_fremovexattr
236     common  gettid                          sys_gettid
237     common  tkill                           sys_tkill
238     common  futex                           sys_futex
239     common  sched_setaffinity               sys_sched_setaffinity
240     common  sched_getaffinity               sys_sched_getaffinity
241     common  tgkill                          sys_tgkill
243     common  io_setup                        sys_io_setup
244     common  io_destroy                      sys_io_destroy
245     common  io_getevents                    sys_io_getevents
246     common  io_submit                       sys_io_submit
247     common  io_cancel                       sys_io_cancel
248     common  exit_group                      sys_exit_group
249     common  epoll_create                    sys_epoll_create
250     common  epoll_ctl                       sys_epoll_ctl
251     common  epoll_wait                      sys_epoll_wait
252     common  set_tid_address                 sys_set_tid_address
253     common  fadvise64                       sys_fadvise64_64
254     common  timer_create                    sys_timer_create
255     common  timer_settime                   sys_timer_settime
256     common  timer_gettime                   sys_timer_gettime
257     common  timer_getoverrun                sys_timer_getoverrun
258     common  timer_delete                    sys_timer_delete
259     common  clock_settime                   sys_clock_settime
260     common  clock_gettime                   sys_clock_gettime
261     common  clock_getres                    sys_clock_getres
262     common  clock_nanosleep                 sys_clock_nanosleep
265     common  statfs64                        sys_statfs64
266     common  fstatfs64                       sys_fstatfs64
267     common  remap_file_pages                sys_remap_file_pages
268     common  mbind                           sys_mbind
269     common  get_mempolicy                   sys_get_mempolicy
270     common  set_mempolicy                   sys_set_mempolicy
271     common  mq_open                         sys_mq_open
272     common  mq_unlink                       sys_mq_unlink
273     common  mq_timedsend                    sys_mq_timedsend
274     common  mq_timedreceive                 sys_mq_timedreceive
275     common  mq_notify                       sys_mq_notify
276     common  mq_getsetattr                   sys_mq_getsetattr
277     common  kexec_load                      sys_kexec_load
278     common  add_key                         sys_add_key
279     common  request_key                     sys_request_key
280     common  keyctl                          sys_keyctl
281     common  waitid                          sys_waitid
282     common  ioprio_set                      sys_ioprio_set
283     common  ioprio_get                      sys_ioprio_get
284     common  inotify_init                    sys_inotify_init
285     common  inotify_add_watch               sys_inotify_add_watch
286     common  inotify_rm_watch                sys_inotify_rm_watch
287     common  migrate_pages                   sys_migrate_pages
288     common  openat                          sys_openat
289     common  mkdirat                         sys_mkdirat
290     common  mknodat                         sys_mknodat
291     common  fchownat                        sys_fchownat
292     common  futimesat                       sys_futimesat
293     common  newfstatat                      sys_newfstatat
294     common  unlinkat                        sys_unlinkat
295     common  renameat                        sys_renameat
296     common  linkat                          sys_linkat
297     common  symlinkat                       sys_symlinkat
298     common  readlinkat                      sys_readlinkat
299     common  fchmodat                        sys_fchmodat
300     common  faccessat                       sys_faccessat
301     common  pselect6                        sys_pselect6
302     common  ppoll                           sys_ppoll
303     common  unshare                         sys_unshare
304     common  set_robust_list                 sys_set_robust_list
305     common  get_robust_list                 sys_get_robust_list
306     common  splice                          sys_splice
307     common  sync_file_range                 sys_sync_file_range
308     common  tee                             sys_tee
309     common  vmsplice                        sys_vmsplice
310     common  move_pages                      sys_move_pages
311     common  getcpu                          sys_getcpu
312     common  epoll_pwait                     sys_epoll_pwait
313     common  utimes                          sys_utimes
314     common  fallocate                       sys_fallocate
315     common  utimensat                       sys_utimensat
316     common  signalfd                        sys_signalfd
317     common  timerfd                         sys_ni_syscall
318     common  eventfd                         sys_eventfd
319     common  timerfd_create                  sys_timerfd_create
320     common  timerfd_settime                 sys_timerfd_settime
321     common  timerfd_gettime                 sys_timerfd_gettime
322     common  signalfd4                       sys_signalfd4
323     common  eventfd2                        sys_eventfd2
324     common  inotify_init1                   sys_inotify_init1
325     common  pipe2                           sys_pipe2
326     common  dup3                            sys_dup3
327     common  epoll_create1                   sys_epoll_create1
328     common  preadv                          sys_preadv
329     common  pwritev                         sys_pwritev
330     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
331     common  perf_event_open                 sys_perf_event_open
332     common  fanotify_init                   sys_fanotify_init
333     common  fanotify_mark                   sys_fanotify_mark
334     common  prlimit64                       sys_prlimit64
335     common  name_to_handle_at               sys_name_to_handle_at
336     common  open_by_handle_at               sys_open_by_handle_at
337     common  clock_adjtime                   sys_clock_adjtime
338     common  syncfs                          sys_syncfs
339     common  setns                           sys_setns
340     common  process_vm_readv                sys_process_vm_readv
341     common  process_vm_writev               sys_process_vm_writev
342     common  s390_runtime_instr              sys_s390_runtime_instr
343     common  kcmp                            sys_kcmp
344     common  finit_module                    sys_finit_module
345     common  sched_setattr                   sys_sched_setattr
346     common  sched_getattr                   sys_sched_getattr
347     common  renameat2                       sys_renameat2
348     common  seccomp                         sys_seccomp
349     common  getrandom                       sys_getrandom
350     common  memfd_create                    sys_memfd_create
351     common  bpf                             sys_bpf
352     common  s390_pci_mmio_write             sys_s390_pci_mmio_write
353     common  s390_pci_mmio_read              sys_s390_pci_mmio_read
354     common  execveat                        sys_execveat
355     common  userfaultfd                     sys_userfaultfd
356     common  membarrier                      sys_membarrier
357     common  recvmmsg                        sys_recvmmsg
358     common  sendmmsg                        sys_sendmmsg
359     common  socket                          sys_socket
360     common  socketpair                      sys_socketpair
361     common  bind                            sys_bind
362     common  connect                         sys_connect
363     common  listen                          sys_listen
364     common  accept4                         sys_accept4
365     common  getsockopt                      sys_getsockopt
366     common  setsockopt                      sys_setsockopt
367     common  getsockname                     sys_getsockname
368     common  getpeername                     sys_getpeername
369     common  sendto                          sys_sendto
370     common  sendmsg                         sys_sendmsg
371     common  recvfrom                        sys_recvfrom
372     common  recvmsg                         sys_recvmsg
373     common  shutdown                        sys_shutdown
374     common  mlock2                          sys_mlock2
375     common  copy_file_range                 sys_copy_file_range
376     common  preadv2                         sys_preadv2
377     common  pwritev2                        sys_pwritev2
378     common  s390_guarded_storage            sys_s390_guarded_storage
379     common  statx                           sys_statx
380     common  s390_sthyi                      sys_s390_sthyi
381     common  kexec_file_load                 sys_kexec_file_load
382     common  io_pgetevents                   sys_io_pgetevents
383     common  rseq                            sys_rseq
384     common  pkey_mprotect                   sys_pkey_mprotect
385     common  pkey_alloc                      sys_pkey_alloc
386     common  pkey_free                       sys_pkey_free
392     common  semtimedop                      sys_semtimedop
393     common  semget                          sys_semget
394     common  semctl                          sys_semctl
395     common  shmget                          sys_shmget
396     common  shmctl                          sys_shmctl
397     common  shmat                           sys_shmat
398     common  shmdt                           sys_shmdt
399     common  msgget                          sys_msgget
400     common  msgsnd                          sys_msgsnd
401     common  msgrcv                          sys_msgrcv
402     common  msgctl                          sys_msgctl
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
447     common  memfd_secret                    sys_memfd_secret
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# SH4
# - arch/sh/kernel/syscalls/syscall.tbl
sh4_syscall_tbl = """
0       common  restart_syscall                 sys_restart_syscall
1       common  exit                            sys_exit
2       common  fork                            sys_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  open                            sys_open
6       common  close                           sys_close
7       common  waitpid                         sys_waitpid
8       common  creat                           sys_creat
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      common  execve                          sys_execve
12      common  chdir                           sys_chdir
13      common  time                            sys_time32
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
16      common  lchown                          sys_lchown16
18      common  oldstat                         sys_stat
19      common  lseek                           sys_lseek
20      common  getpid                          sys_getpid
21      common  mount                           sys_mount
22      common  umount                          sys_oldumount
23      common  setuid                          sys_setuid16
24      common  getuid                          sys_getuid16
25      common  stime                           sys_stime32
26      common  ptrace                          sys_ptrace
27      common  alarm                           sys_alarm
28      common  oldfstat                        sys_fstat
29      common  pause                           sys_pause
30      common  utime                           sys_utime32
33      common  access                          sys_access
34      common  nice                            sys_nice
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  rename                          sys_rename
39      common  mkdir                           sys_mkdir
40      common  rmdir                           sys_rmdir
41      common  dup                             sys_dup
42      common  pipe                            sys_sh_pipe
43      common  times                           sys_times
45      common  brk                             sys_brk
46      common  setgid                          sys_setgid16
47      common  getgid                          sys_getgid16
48      common  signal                          sys_signal
49      common  geteuid                         sys_geteuid16
50      common  getegid                         sys_getegid16
51      common  acct                            sys_acct
52      common  umount2                         sys_umount
54      common  ioctl                           sys_ioctl
55      common  fcntl                           sys_fcntl
57      common  setpgid                         sys_setpgid
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      common  ustat                           sys_ustat
63      common  dup2                            sys_dup2
64      common  getppid                         sys_getppid
65      common  getpgrp                         sys_getpgrp
66      common  setsid                          sys_setsid
67      common  sigaction                       sys_sigaction
68      common  sgetmask                        sys_sgetmask
69      common  ssetmask                        sys_ssetmask
70      common  setreuid                        sys_setreuid16
71      common  setregid                        sys_setregid16
72      common  sigsuspend                      sys_sigsuspend
73      common  sigpending                      sys_sigpending
74      common  sethostname                     sys_sethostname
75      common  setrlimit                       sys_setrlimit
76      common  getrlimit                       sys_old_getrlimit
77      common  getrusage                       sys_getrusage
78      common  gettimeofday                    sys_gettimeofday
79      common  settimeofday                    sys_settimeofday
80      common  getgroups                       sys_getgroups16
81      common  setgroups                       sys_setgroups16
83      common  symlink                         sys_symlink
84      common  oldlstat                        sys_lstat
85      common  readlink                        sys_readlink
86      common  uselib                          sys_uselib
87      common  swapon                          sys_swapon
88      common  reboot                          sys_reboot
89      common  readdir                         sys_old_readdir
90      common  mmap                            old_mmap
91      common  munmap                          sys_munmap
92      common  truncate                        sys_truncate
93      common  ftruncate                       sys_ftruncate
94      common  fchmod                          sys_fchmod
95      common  fchown                          sys_fchown16
96      common  getpriority                     sys_getpriority
97      common  setpriority                     sys_setpriority
99      common  statfs                          sys_statfs
100     common  fstatfs                         sys_fstatfs
102     common  socketcall                      sys_socketcall
103     common  syslog                          sys_syslog
104     common  setitimer                       sys_setitimer
105     common  getitimer                       sys_getitimer
106     common  stat                            sys_newstat
107     common  lstat                           sys_newlstat
108     common  fstat                           sys_newfstat
109     common  olduname                        sys_uname
111     common  vhangup                         sys_vhangup
114     common  wait4                           sys_wait4
115     common  swapoff                         sys_swapoff
116     common  sysinfo                         sys_sysinfo
117     common  ipc                             sys_ipc
118     common  fsync                           sys_fsync
119     common  sigreturn                       sys_sigreturn
120     common  clone                           sys_clone
121     common  setdomainname                   sys_setdomainname
122     common  uname                           sys_newuname
123     common  cacheflush                      sys_cacheflush
124     common  adjtimex                        sys_adjtimex_time32
125     common  mprotect                        sys_mprotect
126     common  sigprocmask                     sys_sigprocmask
128     common  init_module                     sys_init_module
129     common  delete_module                   sys_delete_module
131     common  quotactl                        sys_quotactl
132     common  getpgid                         sys_getpgid
133     common  fchdir                          sys_fchdir
134     common  bdflush                         sys_ni_syscall
135     common  sysfs                           sys_sysfs
136     common  personality                     sys_personality
138     common  setfsuid                        sys_setfsuid16
139     common  setfsgid                        sys_setfsgid16
140     common  _llseek                         sys_llseek
141     common  getdents                        sys_getdents
142     common  _newselect                      sys_select
143     common  flock                           sys_flock
144     common  msync                           sys_msync
145     common  readv                           sys_readv
146     common  writev                          sys_writev
147     common  getsid                          sys_getsid
148     common  fdatasync                       sys_fdatasync
149     common  _sysctl                         sys_ni_syscall
150     common  mlock                           sys_mlock
151     common  munlock                         sys_munlock
152     common  mlockall                        sys_mlockall
153     common  munlockall                      sys_munlockall
154     common  sched_setparam                  sys_sched_setparam
155     common  sched_getparam                  sys_sched_getparam
156     common  sched_setscheduler              sys_sched_setscheduler
157     common  sched_getscheduler              sys_sched_getscheduler
158     common  sched_yield                     sys_sched_yield
159     common  sched_get_priority_max          sys_sched_get_priority_max
160     common  sched_get_priority_min          sys_sched_get_priority_min
161     common  sched_rr_get_interval           sys_sched_rr_get_interval_time32
162     common  nanosleep                       sys_nanosleep_time32
163     common  mremap                          sys_mremap
164     common  setresuid                       sys_setresuid16
165     common  getresuid                       sys_getresuid16
168     common  poll                            sys_poll
169     common  nfsservctl                      sys_ni_syscall
170     common  setresgid                       sys_setresgid16
171     common  getresgid                       sys_getresgid16
172     common  prctl                           sys_prctl
173     common  rt_sigreturn                    sys_rt_sigreturn
174     common  rt_sigaction                    sys_rt_sigaction
175     common  rt_sigprocmask                  sys_rt_sigprocmask
176     common  rt_sigpending                   sys_rt_sigpending
177     common  rt_sigtimedwait                 sys_rt_sigtimedwait_time32
178     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
179     common  rt_sigsuspend                   sys_rt_sigsuspend
180     common  pread64                         sys_pread_wrapper
181     common  pwrite64                        sys_pwrite_wrapper
182     common  chown                           sys_chown16
183     common  getcwd                          sys_getcwd
184     common  capget                          sys_capget
185     common  capset                          sys_capset
186     common  sigaltstack                     sys_sigaltstack
187     common  sendfile                        sys_sendfile
190     common  vfork                           sys_vfork
191     common  ugetrlimit                      sys_getrlimit
192     common  mmap2                           sys_mmap2
193     common  truncate64                      sys_truncate64
194     common  ftruncate64                     sys_ftruncate64
195     common  stat64                          sys_stat64
196     common  lstat64                         sys_lstat64
197     common  fstat64                         sys_fstat64
198     common  lchown32                        sys_lchown
199     common  getuid32                        sys_getuid
200     common  getgid32                        sys_getgid
201     common  geteuid32                       sys_geteuid
202     common  getegid32                       sys_getegid
203     common  setreuid32                      sys_setreuid
204     common  setregid32                      sys_setregid
205     common  getgroups32                     sys_getgroups
206     common  setgroups32                     sys_setgroups
207     common  fchown32                        sys_fchown
208     common  setresuid32                     sys_setresuid
209     common  getresuid32                     sys_getresuid
210     common  setresgid32                     sys_setresgid
211     common  getresgid32                     sys_getresgid
212     common  chown32                         sys_chown
213     common  setuid32                        sys_setuid
214     common  setgid32                        sys_setgid
215     common  setfsuid32                      sys_setfsuid
216     common  setfsgid32                      sys_setfsgid
217     common  pivot_root                      sys_pivot_root
218     common  mincore                         sys_mincore
219     common  madvise                         sys_madvise
220     common  getdents64                      sys_getdents64
221     common  fcntl64                         sys_fcntl64
224     common  gettid                          sys_gettid
225     common  readahead                       sys_readahead
226     common  setxattr                        sys_setxattr
227     common  lsetxattr                       sys_lsetxattr
228     common  fsetxattr                       sys_fsetxattr
229     common  getxattr                        sys_getxattr
230     common  lgetxattr                       sys_lgetxattr
231     common  fgetxattr                       sys_fgetxattr
232     common  listxattr                       sys_listxattr
233     common  llistxattr                      sys_llistxattr
234     common  flistxattr                      sys_flistxattr
235     common  removexattr                     sys_removexattr
236     common  lremovexattr                    sys_lremovexattr
237     common  fremovexattr                    sys_fremovexattr
238     common  tkill                           sys_tkill
239     common  sendfile64                      sys_sendfile64
240     common  futex                           sys_futex_time32
241     common  sched_setaffinity               sys_sched_setaffinity
242     common  sched_getaffinity               sys_sched_getaffinity
245     common  io_setup                        sys_io_setup
246     common  io_destroy                      sys_io_destroy
247     common  io_getevents                    sys_io_getevents_time32
248     common  io_submit                       sys_io_submit
249     common  io_cancel                       sys_io_cancel
250     common  fadvise64                       sys_fadvise64
252     common  exit_group                      sys_exit_group
253     common  lookup_dcookie                  sys_ni_syscall
254     common  epoll_create                    sys_epoll_create
255     common  epoll_ctl                       sys_epoll_ctl
256     common  epoll_wait                      sys_epoll_wait
257     common  remap_file_pages                sys_remap_file_pages
258     common  set_tid_address                 sys_set_tid_address
259     common  timer_create                    sys_timer_create
260     common  timer_settime                   sys_timer_settime32
261     common  timer_gettime                   sys_timer_gettime32
262     common  timer_getoverrun                sys_timer_getoverrun
263     common  timer_delete                    sys_timer_delete
264     common  clock_settime                   sys_clock_settime32
265     common  clock_gettime                   sys_clock_gettime32
266     common  clock_getres                    sys_clock_getres_time32
267     common  clock_nanosleep                 sys_clock_nanosleep_time32
268     common  statfs64                        sys_statfs64
269     common  fstatfs64                       sys_fstatfs64
270     common  tgkill                          sys_tgkill
271     common  utimes                          sys_utimes_time32
272     common  fadvise64_64                    sys_fadvise64_64_wrapper
274     common  mbind                           sys_mbind
275     common  get_mempolicy                   sys_get_mempolicy
276     common  set_mempolicy                   sys_set_mempolicy
277     common  mq_open                         sys_mq_open
278     common  mq_unlink                       sys_mq_unlink
279     common  mq_timedsend                    sys_mq_timedsend_time32
280     common  mq_timedreceive                 sys_mq_timedreceive_time32
281     common  mq_notify                       sys_mq_notify
282     common  mq_getsetattr                   sys_mq_getsetattr
283     common  kexec_load                      sys_kexec_load
284     common  waitid                          sys_waitid
285     common  add_key                         sys_add_key
286     common  request_key                     sys_request_key
287     common  keyctl                          sys_keyctl
288     common  ioprio_set                      sys_ioprio_set
289     common  ioprio_get                      sys_ioprio_get
290     common  inotify_init                    sys_inotify_init
291     common  inotify_add_watch               sys_inotify_add_watch
292     common  inotify_rm_watch                sys_inotify_rm_watch
294     common  migrate_pages                   sys_migrate_pages
295     common  openat                          sys_openat
296     common  mkdirat                         sys_mkdirat
297     common  mknodat                         sys_mknodat
298     common  fchownat                        sys_fchownat
299     common  futimesat                       sys_futimesat_time32
300     common  fstatat64                       sys_fstatat64
301     common  unlinkat                        sys_unlinkat
302     common  renameat                        sys_renameat
303     common  linkat                          sys_linkat
304     common  symlinkat                       sys_symlinkat
305     common  readlinkat                      sys_readlinkat
306     common  fchmodat                        sys_fchmodat
307     common  faccessat                       sys_faccessat
308     common  pselect6                        sys_pselect6_time32
309     common  ppoll                           sys_ppoll_time32
310     common  unshare                         sys_unshare
311     common  set_robust_list                 sys_set_robust_list
312     common  get_robust_list                 sys_get_robust_list
313     common  splice                          sys_splice
314     common  sync_file_range                 sys_sh_sync_file_range6
315     common  tee                             sys_tee
316     common  vmsplice                        sys_vmsplice
317     common  move_pages                      sys_move_pages
318     common  getcpu                          sys_getcpu
319     common  epoll_pwait                     sys_epoll_pwait
320     common  utimensat                       sys_utimensat_time32
321     common  signalfd                        sys_signalfd
322     common  timerfd_create                  sys_timerfd_create
323     common  eventfd                         sys_eventfd
324     common  fallocate                       sys_fallocate
325     common  timerfd_settime                 sys_timerfd_settime32
326     common  timerfd_gettime                 sys_timerfd_gettime32
327     common  signalfd4                       sys_signalfd4
328     common  eventfd2                        sys_eventfd2
329     common  epoll_create1                   sys_epoll_create1
330     common  dup3                            sys_dup3
331     common  pipe2                           sys_pipe2
332     common  inotify_init1                   sys_inotify_init1
333     common  preadv                          sys_preadv
334     common  pwritev                         sys_pwritev
335     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
336     common  perf_event_open                 sys_perf_event_open
337     common  fanotify_init                   sys_fanotify_init
338     common  fanotify_mark                   sys_fanotify_mark
339     common  prlimit64                       sys_prlimit64
340     common  socket                          sys_socket
341     common  bind                            sys_bind
342     common  connect                         sys_connect
343     common  listen                          sys_listen
344     common  accept                          sys_accept
345     common  getsockname                     sys_getsockname
346     common  getpeername                     sys_getpeername
347     common  socketpair                      sys_socketpair
348     common  send                            sys_send
349     common  sendto                          sys_sendto
350     common  recv                            sys_recv
351     common  recvfrom                        sys_recvfrom
352     common  shutdown                        sys_shutdown
353     common  setsockopt                      sys_setsockopt
354     common  getsockopt                      sys_getsockopt
355     common  sendmsg                         sys_sendmsg
356     common  recvmsg                         sys_recvmsg
357     common  recvmmsg                        sys_recvmmsg_time32
358     common  accept4                         sys_accept4
359     common  name_to_handle_at               sys_name_to_handle_at
360     common  open_by_handle_at               sys_open_by_handle_at
361     common  clock_adjtime                   sys_clock_adjtime32
362     common  syncfs                          sys_syncfs
363     common  sendmmsg                        sys_sendmmsg
364     common  setns                           sys_setns
365     common  process_vm_readv                sys_process_vm_readv
366     common  process_vm_writev               sys_process_vm_writev
367     common  kcmp                            sys_kcmp
368     common  finit_module                    sys_finit_module
369     common  sched_getattr                   sys_sched_getattr
370     common  sched_setattr                   sys_sched_setattr
371     common  renameat2                       sys_renameat2
372     common  seccomp                         sys_seccomp
373     common  getrandom                       sys_getrandom
374     common  memfd_create                    sys_memfd_create
375     common  bpf                             sys_bpf
376     common  execveat                        sys_execveat
377     common  userfaultfd                     sys_userfaultfd
378     common  membarrier                      sys_membarrier
379     common  mlock2                          sys_mlock2
380     common  copy_file_range                 sys_copy_file_range
381     common  preadv2                         sys_preadv2
382     common  pwritev2                        sys_pwritev2
383     common  statx                           sys_statx
384     common  pkey_mprotect                   sys_pkey_mprotect
385     common  pkey_alloc                      sys_pkey_alloc
386     common  pkey_free                       sys_pkey_free
387     common  rseq                            sys_rseq
388     common  sync_file_range2                sys_sync_file_range2
393     common  semget                          sys_semget
394     common  semctl                          sys_semctl
395     common  shmget                          sys_shmget
396     common  shmctl                          sys_shmctl
397     common  shmat                           sys_shmat
398     common  shmdt                           sys_shmdt
399     common  msgget                          sys_msgget
400     common  msgsnd                          sys_msgsnd
401     common  msgrcv                          sys_msgrcv
402     common  msgctl                          sys_msgctl
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6
414     common  ppoll_time64                    sys_ppoll
416     common  io_pgetevents_time64            sys_io_pgetevents
417     common  recvmmsg_time64                 sys_recvmmsg
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# m68k
# - arch/m68k/kernel/syscalls/syscall.tbl
m68k_syscall_tbl = """
0       common  restart_syscall                 sys_restart_syscall
1       common  exit                            sys_exit
2       common  fork                            __sys_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  open                            sys_open
6       common  close                           sys_close
7       common  waitpid                         sys_waitpid
8       common  creat                           sys_creat
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      common  execve                          sys_execve
12      common  chdir                           sys_chdir
13      common  time                            sys_time32
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
16      common  chown                           sys_chown16
18      common  oldstat                         sys_stat
19      common  lseek                           sys_lseek
20      common  getpid                          sys_getpid
21      common  mount                           sys_mount
22      common  umount                          sys_oldumount
23      common  setuid                          sys_setuid16
24      common  getuid                          sys_getuid16
25      common  stime                           sys_stime32
26      common  ptrace                          sys_ptrace
27      common  alarm                           sys_alarm
28      common  oldfstat                        sys_fstat
29      common  pause                           sys_pause
30      common  utime                           sys_utime32
33      common  access                          sys_access
34      common  nice                            sys_nice
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  rename                          sys_rename
39      common  mkdir                           sys_mkdir
40      common  rmdir                           sys_rmdir
41      common  dup                             sys_dup
42      common  pipe                            sys_pipe
43      common  times                           sys_times
45      common  brk                             sys_brk
46      common  setgid                          sys_setgid16
47      common  getgid                          sys_getgid16
48      common  signal                          sys_signal
49      common  geteuid                         sys_geteuid16
50      common  getegid                         sys_getegid16
51      common  acct                            sys_acct
52      common  umount2                         sys_umount
54      common  ioctl                           sys_ioctl
55      common  fcntl                           sys_fcntl
57      common  setpgid                         sys_setpgid
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      common  ustat                           sys_ustat
63      common  dup2                            sys_dup2
64      common  getppid                         sys_getppid
65      common  getpgrp                         sys_getpgrp
66      common  setsid                          sys_setsid
67      common  sigaction                       sys_sigaction
68      common  sgetmask                        sys_sgetmask
69      common  ssetmask                        sys_ssetmask
70      common  setreuid                        sys_setreuid16
71      common  setregid                        sys_setregid16
72      common  sigsuspend                      sys_sigsuspend
73      common  sigpending                      sys_sigpending
74      common  sethostname                     sys_sethostname
75      common  setrlimit                       sys_setrlimit
76      common  getrlimit                       sys_old_getrlimit
77      common  getrusage                       sys_getrusage
78      common  gettimeofday                    sys_gettimeofday
79      common  settimeofday                    sys_settimeofday
80      common  getgroups                       sys_getgroups16
81      common  setgroups                       sys_setgroups16
82      common  select                          sys_old_select
83      common  symlink                         sys_symlink
84      common  oldlstat                        sys_lstat
85      common  readlink                        sys_readlink
86      common  uselib                          sys_uselib
87      common  swapon                          sys_swapon
88      common  reboot                          sys_reboot
89      common  readdir                         sys_old_readdir
90      common  mmap                            sys_old_mmap
91      common  munmap                          sys_munmap
92      common  truncate                        sys_truncate
93      common  ftruncate                       sys_ftruncate
94      common  fchmod                          sys_fchmod
95      common  fchown                          sys_fchown16
96      common  getpriority                     sys_getpriority
97      common  setpriority                     sys_setpriority
99      common  statfs                          sys_statfs
100     common  fstatfs                         sys_fstatfs
102     common  socketcall                      sys_socketcall
103     common  syslog                          sys_syslog
104     common  setitimer                       sys_setitimer
105     common  getitimer                       sys_getitimer
106     common  stat                            sys_newstat
107     common  lstat                           sys_newlstat
108     common  fstat                           sys_newfstat
111     common  vhangup                         sys_vhangup
114     common  wait4                           sys_wait4
115     common  swapoff                         sys_swapoff
116     common  sysinfo                         sys_sysinfo
117     common  ipc                             sys_ipc
118     common  fsync                           sys_fsync
119     common  sigreturn                       sys_sigreturn
120     common  clone                           __sys_clone
121     common  setdomainname                   sys_setdomainname
122     common  uname                           sys_newuname
123     common  cacheflush                      sys_cacheflush
124     common  adjtimex                        sys_adjtimex_time32
125     common  mprotect                        sys_mprotect
126     common  sigprocmask                     sys_sigprocmask
127     common  create_module                   sys_ni_syscall
128     common  init_module                     sys_init_module
129     common  delete_module                   sys_delete_module
130     common  get_kernel_syms                 sys_ni_syscall
131     common  quotactl                        sys_quotactl
132     common  getpgid                         sys_getpgid
133     common  fchdir                          sys_fchdir
134     common  bdflush                         sys_ni_syscall
135     common  sysfs                           sys_sysfs
136     common  personality                     sys_personality
138     common  setfsuid                        sys_setfsuid16
139     common  setfsgid                        sys_setfsgid16
140     common  _llseek                         sys_llseek
141     common  getdents                        sys_getdents
142     common  _newselect                      sys_select
143     common  flock                           sys_flock
144     common  msync                           sys_msync
145     common  readv                           sys_readv
146     common  writev                          sys_writev
147     common  getsid                          sys_getsid
148     common  fdatasync                       sys_fdatasync
149     common  _sysctl                         sys_ni_syscall
150     common  mlock                           sys_mlock
151     common  munlock                         sys_munlock
152     common  mlockall                        sys_mlockall
153     common  munlockall                      sys_munlockall
154     common  sched_setparam                  sys_sched_setparam
155     common  sched_getparam                  sys_sched_getparam
156     common  sched_setscheduler              sys_sched_setscheduler
157     common  sched_getscheduler              sys_sched_getscheduler
158     common  sched_yield                     sys_sched_yield
159     common  sched_get_priority_max          sys_sched_get_priority_max
160     common  sched_get_priority_min          sys_sched_get_priority_min
161     common  sched_rr_get_interval           sys_sched_rr_get_interval_time32
162     common  nanosleep                       sys_nanosleep_time32
163     common  mremap                          sys_mremap
164     common  setresuid                       sys_setresuid16
165     common  getresuid                       sys_getresuid16
166     common  getpagesize                     sys_getpagesize
167     common  query_module                    sys_ni_syscall
168     common  poll                            sys_poll
169     common  nfsservctl                      sys_ni_syscall
170     common  setresgid                       sys_setresgid16
171     common  getresgid                       sys_getresgid16
172     common  prctl                           sys_prctl
173     common  rt_sigreturn                    sys_rt_sigreturn
174     common  rt_sigaction                    sys_rt_sigaction
175     common  rt_sigprocmask                  sys_rt_sigprocmask
176     common  rt_sigpending                   sys_rt_sigpending
177     common  rt_sigtimedwait                 sys_rt_sigtimedwait_time32
178     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
179     common  rt_sigsuspend                   sys_rt_sigsuspend
180     common  pread64                         sys_pread64
181     common  pwrite64                        sys_pwrite64
182     common  lchown                          sys_lchown16
183     common  getcwd                          sys_getcwd
184     common  capget                          sys_capget
185     common  capset                          sys_capset
186     common  sigaltstack                     sys_sigaltstack
187     common  sendfile                        sys_sendfile
188     common  getpmsg                         sys_ni_syscall
189     common  putpmsg                         sys_ni_syscall
190     common  vfork                           __sys_vfork
191     common  ugetrlimit                      sys_getrlimit
192     common  mmap2                           sys_mmap2
193     common  truncate64                      sys_truncate64
194     common  ftruncate64                     sys_ftruncate64
195     common  stat64                          sys_stat64
196     common  lstat64                         sys_lstat64
197     common  fstat64                         sys_fstat64
198     common  chown32                         sys_chown
199     common  getuid32                        sys_getuid
200     common  getgid32                        sys_getgid
201     common  geteuid32                       sys_geteuid
202     common  getegid32                       sys_getegid
203     common  setreuid32                      sys_setreuid
204     common  setregid32                      sys_setregid
205     common  getgroups32                     sys_getgroups
206     common  setgroups32                     sys_setgroups
207     common  fchown32                        sys_fchown
208     common  setresuid32                     sys_setresuid
209     common  getresuid32                     sys_getresuid
210     common  setresgid32                     sys_setresgid
211     common  getresgid32                     sys_getresgid
212     common  lchown32                        sys_lchown
213     common  setuid32                        sys_setuid
214     common  setgid32                        sys_setgid
215     common  setfsuid32                      sys_setfsuid
216     common  setfsgid32                      sys_setfsgid
217     common  pivot_root                      sys_pivot_root
220     common  getdents64                      sys_getdents64
221     common  gettid                          sys_gettid
222     common  tkill                           sys_tkill
223     common  setxattr                        sys_setxattr
224     common  lsetxattr                       sys_lsetxattr
225     common  fsetxattr                       sys_fsetxattr
226     common  getxattr                        sys_getxattr
227     common  lgetxattr                       sys_lgetxattr
228     common  fgetxattr                       sys_fgetxattr
229     common  listxattr                       sys_listxattr
230     common  llistxattr                      sys_llistxattr
231     common  flistxattr                      sys_flistxattr
232     common  removexattr                     sys_removexattr
233     common  lremovexattr                    sys_lremovexattr
234     common  fremovexattr                    sys_fremovexattr
235     common  futex                           sys_futex_time32
236     common  sendfile64                      sys_sendfile64
237     common  mincore                         sys_mincore
238     common  madvise                         sys_madvise
239     common  fcntl64                         sys_fcntl64
240     common  readahead                       sys_readahead
241     common  io_setup                        sys_io_setup
242     common  io_destroy                      sys_io_destroy
243     common  io_getevents                    sys_io_getevents_time32
244     common  io_submit                       sys_io_submit
245     common  io_cancel                       sys_io_cancel
246     common  fadvise64                       sys_fadvise64
247     common  exit_group                      sys_exit_group
248     common  lookup_dcookie                  sys_ni_syscall
249     common  epoll_create                    sys_epoll_create
250     common  epoll_ctl                       sys_epoll_ctl
251     common  epoll_wait                      sys_epoll_wait
252     common  remap_file_pages                sys_remap_file_pages
253     common  set_tid_address                 sys_set_tid_address
254     common  timer_create                    sys_timer_create
255     common  timer_settime                   sys_timer_settime32
256     common  timer_gettime                   sys_timer_gettime32
257     common  timer_getoverrun                sys_timer_getoverrun
258     common  timer_delete                    sys_timer_delete
259     common  clock_settime                   sys_clock_settime32
260     common  clock_gettime                   sys_clock_gettime32
261     common  clock_getres                    sys_clock_getres_time32
262     common  clock_nanosleep                 sys_clock_nanosleep_time32
263     common  statfs64                        sys_statfs64
264     common  fstatfs64                       sys_fstatfs64
265     common  tgkill                          sys_tgkill
266     common  utimes                          sys_utimes_time32
267     common  fadvise64_64                    sys_fadvise64_64
268     common  mbind                           sys_mbind
269     common  get_mempolicy                   sys_get_mempolicy
270     common  set_mempolicy                   sys_set_mempolicy
271     common  mq_open                         sys_mq_open
272     common  mq_unlink                       sys_mq_unlink
273     common  mq_timedsend                    sys_mq_timedsend_time32
274     common  mq_timedreceive                 sys_mq_timedreceive_time32
275     common  mq_notify                       sys_mq_notify
276     common  mq_getsetattr                   sys_mq_getsetattr
277     common  waitid                          sys_waitid
279     common  add_key                         sys_add_key
280     common  request_key                     sys_request_key
281     common  keyctl                          sys_keyctl
282     common  ioprio_set                      sys_ioprio_set
283     common  ioprio_get                      sys_ioprio_get
284     common  inotify_init                    sys_inotify_init
285     common  inotify_add_watch               sys_inotify_add_watch
286     common  inotify_rm_watch                sys_inotify_rm_watch
287     common  migrate_pages                   sys_migrate_pages
288     common  openat                          sys_openat
289     common  mkdirat                         sys_mkdirat
290     common  mknodat                         sys_mknodat
291     common  fchownat                        sys_fchownat
292     common  futimesat                       sys_futimesat_time32
293     common  fstatat64                       sys_fstatat64
294     common  unlinkat                        sys_unlinkat
295     common  renameat                        sys_renameat
296     common  linkat                          sys_linkat
297     common  symlinkat                       sys_symlinkat
298     common  readlinkat                      sys_readlinkat
299     common  fchmodat                        sys_fchmodat
300     common  faccessat                       sys_faccessat
301     common  pselect6                        sys_pselect6_time32
302     common  ppoll                           sys_ppoll_time32
303     common  unshare                         sys_unshare
304     common  set_robust_list                 sys_set_robust_list
305     common  get_robust_list                 sys_get_robust_list
306     common  splice                          sys_splice
307     common  sync_file_range                 sys_sync_file_range
308     common  tee                             sys_tee
309     common  vmsplice                        sys_vmsplice
310     common  move_pages                      sys_move_pages
311     common  sched_setaffinity               sys_sched_setaffinity
312     common  sched_getaffinity               sys_sched_getaffinity
313     common  kexec_load                      sys_kexec_load
314     common  getcpu                          sys_getcpu
315     common  epoll_pwait                     sys_epoll_pwait
316     common  utimensat                       sys_utimensat_time32
317     common  signalfd                        sys_signalfd
318     common  timerfd_create                  sys_timerfd_create
319     common  eventfd                         sys_eventfd
320     common  fallocate                       sys_fallocate
321     common  timerfd_settime                 sys_timerfd_settime32
322     common  timerfd_gettime                 sys_timerfd_gettime32
323     common  signalfd4                       sys_signalfd4
324     common  eventfd2                        sys_eventfd2
325     common  epoll_create1                   sys_epoll_create1
326     common  dup3                            sys_dup3
327     common  pipe2                           sys_pipe2
328     common  inotify_init1                   sys_inotify_init1
329     common  preadv                          sys_preadv
330     common  pwritev                         sys_pwritev
331     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
332     common  perf_event_open                 sys_perf_event_open
333     common  get_thread_area                 sys_get_thread_area
334     common  set_thread_area                 sys_set_thread_area
335     common  atomic_cmpxchg_32               sys_atomic_cmpxchg_32
336     common  atomic_barrier                  sys_atomic_barrier
337     common  fanotify_init                   sys_fanotify_init
338     common  fanotify_mark                   sys_fanotify_mark
339     common  prlimit64                       sys_prlimit64
340     common  name_to_handle_at               sys_name_to_handle_at
341     common  open_by_handle_at               sys_open_by_handle_at
342     common  clock_adjtime                   sys_clock_adjtime32
343     common  syncfs                          sys_syncfs
344     common  setns                           sys_setns
345     common  process_vm_readv                sys_process_vm_readv
346     common  process_vm_writev               sys_process_vm_writev
347     common  kcmp                            sys_kcmp
348     common  finit_module                    sys_finit_module
349     common  sched_setattr                   sys_sched_setattr
350     common  sched_getattr                   sys_sched_getattr
351     common  renameat2                       sys_renameat2
352     common  getrandom                       sys_getrandom
353     common  memfd_create                    sys_memfd_create
354     common  bpf                             sys_bpf
355     common  execveat                        sys_execveat
356     common  socket                          sys_socket
357     common  socketpair                      sys_socketpair
358     common  bind                            sys_bind
359     common  connect                         sys_connect
360     common  listen                          sys_listen
361     common  accept4                         sys_accept4
362     common  getsockopt                      sys_getsockopt
363     common  setsockopt                      sys_setsockopt
364     common  getsockname                     sys_getsockname
365     common  getpeername                     sys_getpeername
366     common  sendto                          sys_sendto
367     common  sendmsg                         sys_sendmsg
368     common  recvfrom                        sys_recvfrom
369     common  recvmsg                         sys_recvmsg
370     common  shutdown                        sys_shutdown
371     common  recvmmsg                        sys_recvmmsg_time32
372     common  sendmmsg                        sys_sendmmsg
373     common  userfaultfd                     sys_userfaultfd
374     common  membarrier                      sys_membarrier
375     common  mlock2                          sys_mlock2
376     common  copy_file_range                 sys_copy_file_range
377     common  preadv2                         sys_preadv2
378     common  pwritev2                        sys_pwritev2
379     common  statx                           sys_statx
380     common  seccomp                         sys_seccomp
381     common  pkey_mprotect                   sys_pkey_mprotect
382     common  pkey_alloc                      sys_pkey_alloc
383     common  pkey_free                       sys_pkey_free
384     common  rseq                            sys_rseq
393     common  semget                          sys_semget
394     common  semctl                          sys_semctl
395     common  shmget                          sys_shmget
396     common  shmctl                          sys_shmctl
397     common  shmat                           sys_shmat
398     common  shmdt                           sys_shmdt
399     common  msgget                          sys_msgget
400     common  msgsnd                          sys_msgsnd
401     common  msgrcv                          sys_msgrcv
402     common  msgctl                          sys_msgctl
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6
414     common  ppoll_time64                    sys_ppoll
416     common  io_pgetevents_time64            sys_io_pgetevents
417     common  recvmmsg_time64                 sys_recvmmsg
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          __sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# alpha
# - arch/alpha/kernel/syscalls/syscall.tbl
alpha_syscall_tbl = """
0       common  osf_syscall                     alpha_syscall_zero
1       common  exit                            sys_exit
2       common  fork                            alpha_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  osf_old_open                    sys_ni_syscall
6       common  close                           sys_close
7       common  osf_wait4                       sys_osf_wait4
8       common  osf_old_creat                   sys_ni_syscall
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      common  osf_execve                      sys_ni_syscall
12      common  chdir                           sys_chdir
13      common  fchdir                          sys_fchdir
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
16      common  chown                           sys_chown
17      common  brk                             sys_osf_brk
18      common  osf_getfsstat                   sys_ni_syscall
19      common  lseek                           sys_lseek
20      common  getxpid                         sys_getxpid
21      common  osf_mount                       sys_osf_mount
22      common  umount2                         sys_umount
23      common  setuid                          sys_setuid
24      common  getxuid                         sys_getxuid
25      common  exec_with_loader                sys_ni_syscall
26      common  ptrace                          sys_ptrace
27      common  osf_nrecvmsg                    sys_ni_syscall
28      common  osf_nsendmsg                    sys_ni_syscall
29      common  osf_nrecvfrom                   sys_ni_syscall
30      common  osf_naccept                     sys_ni_syscall
31      common  osf_ngetpeername                sys_ni_syscall
32      common  osf_ngetsockname                sys_ni_syscall
33      common  access                          sys_access
34      common  osf_chflags                     sys_ni_syscall
35      common  osf_fchflags                    sys_ni_syscall
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  osf_old_stat                    sys_ni_syscall
39      common  setpgid                         sys_setpgid
40      common  osf_old_lstat                   sys_ni_syscall
41      common  dup                             sys_dup
42      common  pipe                            sys_alpha_pipe
43      common  osf_set_program_attributes      sys_osf_set_program_attributes
44      common  osf_profil                      sys_ni_syscall
45      common  open                            sys_open
46      common  osf_old_sigaction               sys_ni_syscall
47      common  getxgid                         sys_getxgid
48      common  osf_sigprocmask                 sys_osf_sigprocmask
49      common  osf_getlogin                    sys_ni_syscall
50      common  osf_setlogin                    sys_ni_syscall
51      common  acct                            sys_acct
52      common  sigpending                      sys_sigpending
54      common  ioctl                           sys_ioctl
55      common  osf_reboot                      sys_ni_syscall
56      common  osf_revoke                      sys_ni_syscall
57      common  symlink                         sys_symlink
58      common  readlink                        sys_readlink
59      common  execve                          sys_execve
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      common  osf_old_fstat                   sys_ni_syscall
63      common  getpgrp                         sys_getpgrp
64      common  getpagesize                     sys_getpagesize
65      common  osf_mremap                      sys_ni_syscall
66      common  vfork                           alpha_vfork
67      common  stat                            sys_newstat
68      common  lstat                           sys_newlstat
69      common  osf_sbrk                        sys_ni_syscall
70      common  osf_sstk                        sys_ni_syscall
71      common  mmap                            sys_osf_mmap
72      common  osf_old_vadvise                 sys_ni_syscall
73      common  munmap                          sys_munmap
74      common  mprotect                        sys_mprotect
75      common  madvise                         sys_madvise
76      common  vhangup                         sys_vhangup
77      common  osf_kmodcall                    sys_ni_syscall
78      common  osf_mincore                     sys_ni_syscall
79      common  getgroups                       sys_getgroups
80      common  setgroups                       sys_setgroups
81      common  osf_old_getpgrp                 sys_ni_syscall
82      common  setpgrp                         sys_setpgid
83      common  osf_setitimer                   compat_sys_setitimer
84      common  osf_old_wait                    sys_ni_syscall
85      common  osf_table                       sys_ni_syscall
86      common  osf_getitimer                   compat_sys_getitimer
87      common  gethostname                     sys_gethostname
88      common  sethostname                     sys_sethostname
89      common  getdtablesize                   sys_getdtablesize
90      common  dup2                            sys_dup2
91      common  fstat                           sys_newfstat
92      common  fcntl                           sys_fcntl
93      common  osf_select                      sys_osf_select
94      common  poll                            sys_poll
95      common  fsync                           sys_fsync
96      common  setpriority                     sys_setpriority
97      common  socket                          sys_socket
98      common  connect                         sys_connect
99      common  accept                          sys_accept
100     common  getpriority                     sys_osf_getpriority
101     common  send                            sys_send
102     common  recv                            sys_recv
103     common  sigreturn                       sys_sigreturn
104     common  bind                            sys_bind
105     common  setsockopt                      sys_setsockopt
106     common  listen                          sys_listen
107     common  osf_plock                       sys_ni_syscall
108     common  osf_old_sigvec                  sys_ni_syscall
109     common  osf_old_sigblock                sys_ni_syscall
110     common  osf_old_sigsetmask              sys_ni_syscall
111     common  sigsuspend                      sys_sigsuspend
112     common  osf_sigstack                    sys_osf_sigstack
113     common  recvmsg                         sys_recvmsg
114     common  sendmsg                         sys_sendmsg
115     common  osf_old_vtrace                  sys_ni_syscall
116     common  osf_gettimeofday                sys_osf_gettimeofday
117     common  osf_getrusage                   sys_osf_getrusage
118     common  getsockopt                      sys_getsockopt
120     common  readv                           sys_readv
121     common  writev                          sys_writev
122     common  osf_settimeofday                sys_osf_settimeofday
123     common  fchown                          sys_fchown
124     common  fchmod                          sys_fchmod
125     common  recvfrom                        sys_recvfrom
126     common  setreuid                        sys_setreuid
127     common  setregid                        sys_setregid
128     common  rename                          sys_rename
129     common  truncate                        sys_truncate
130     common  ftruncate                       sys_ftruncate
131     common  flock                           sys_flock
132     common  setgid                          sys_setgid
133     common  sendto                          sys_sendto
134     common  shutdown                        sys_shutdown
135     common  socketpair                      sys_socketpair
136     common  mkdir                           sys_mkdir
137     common  rmdir                           sys_rmdir
138     common  osf_utimes                      sys_osf_utimes
139     common  osf_old_sigreturn               sys_ni_syscall
140     common  osf_adjtime                     sys_ni_syscall
141     common  getpeername                     sys_getpeername
142     common  osf_gethostid                   sys_ni_syscall
143     common  osf_sethostid                   sys_ni_syscall
144     common  getrlimit                       sys_getrlimit
145     common  setrlimit                       sys_setrlimit
146     common  osf_old_killpg                  sys_ni_syscall
147     common  setsid                          sys_setsid
148     common  quotactl                        sys_quotactl
149     common  osf_oldquota                    sys_ni_syscall
150     common  getsockname                     sys_getsockname
153     common  osf_pid_block                   sys_ni_syscall
154     common  osf_pid_unblock                 sys_ni_syscall
156     common  sigaction                       sys_osf_sigaction
157     common  osf_sigwaitprim                 sys_ni_syscall
158     common  osf_nfssvc                      sys_ni_syscall
159     common  osf_getdirentries               sys_osf_getdirentries
160     common  osf_statfs                      sys_osf_statfs
161     common  osf_fstatfs                     sys_osf_fstatfs
163     common  osf_asynch_daemon               sys_ni_syscall
164     common  osf_getfh                       sys_ni_syscall
165     common  osf_getdomainname               sys_osf_getdomainname
166     common  setdomainname                   sys_setdomainname
169     common  osf_exportfs                    sys_ni_syscall
181     common  osf_alt_plock                   sys_ni_syscall
184     common  osf_getmnt                      sys_ni_syscall
187     common  osf_alt_sigpending              sys_ni_syscall
188     common  osf_alt_setsid                  sys_ni_syscall
199     common  osf_swapon                      sys_swapon
200     common  msgctl                          sys_old_msgctl
201     common  msgget                          sys_msgget
202     common  msgrcv                          sys_msgrcv
203     common  msgsnd                          sys_msgsnd
204     common  semctl                          sys_old_semctl
205     common  semget                          sys_semget
206     common  semop                           sys_semop
207     common  osf_utsname                     sys_osf_utsname
208     common  lchown                          sys_lchown
209     common  shmat                           sys_shmat
210     common  shmctl                          sys_old_shmctl
211     common  shmdt                           sys_shmdt
212     common  shmget                          sys_shmget
213     common  osf_mvalid                      sys_ni_syscall
214     common  osf_getaddressconf              sys_ni_syscall
215     common  osf_msleep                      sys_ni_syscall
216     common  osf_mwakeup                     sys_ni_syscall
217     common  msync                           sys_msync
218     common  osf_signal                      sys_ni_syscall
219     common  osf_utc_gettime                 sys_ni_syscall
220     common  osf_utc_adjtime                 sys_ni_syscall
222     common  osf_security                    sys_ni_syscall
223     common  osf_kloadcall                   sys_ni_syscall
224     common  osf_stat                        sys_osf_stat
225     common  osf_lstat                       sys_osf_lstat
226     common  osf_fstat                       sys_osf_fstat
227     common  osf_statfs64                    sys_osf_statfs64
228     common  osf_fstatfs64                   sys_osf_fstatfs64
233     common  getpgid                         sys_getpgid
234     common  getsid                          sys_getsid
235     common  sigaltstack                     sys_sigaltstack
236     common  osf_waitid                      sys_ni_syscall
237     common  osf_priocntlset                 sys_ni_syscall
238     common  osf_sigsendset                  sys_ni_syscall
239     common  osf_set_speculative             sys_ni_syscall
240     common  osf_msfs_syscall                sys_ni_syscall
241     common  osf_sysinfo                     sys_osf_sysinfo
242     common  osf_uadmin                      sys_ni_syscall
243     common  osf_fuser                       sys_ni_syscall
244     common  osf_proplist_syscall            sys_osf_proplist_syscall
245     common  osf_ntp_adjtime                 sys_ni_syscall
246     common  osf_ntp_gettime                 sys_ni_syscall
247     common  osf_pathconf                    sys_ni_syscall
248     common  osf_fpathconf                   sys_ni_syscall
250     common  osf_uswitch                     sys_ni_syscall
251     common  osf_usleep_thread               sys_osf_usleep_thread
252     common  osf_audcntl                     sys_ni_syscall
253     common  osf_audgen                      sys_ni_syscall
254     common  sysfs                           sys_sysfs
255     common  osf_subsys_info                 sys_ni_syscall
256     common  osf_getsysinfo                  sys_osf_getsysinfo
257     common  osf_setsysinfo                  sys_osf_setsysinfo
258     common  osf_afs_syscall                 sys_ni_syscall
259     common  osf_swapctl                     sys_ni_syscall
260     common  osf_memcntl                     sys_ni_syscall
261     common  osf_fdatasync                   sys_ni_syscall
300     common  bdflush                         sys_ni_syscall
301     common  sethae                          sys_sethae
302     common  mount                           sys_mount
303     common  old_adjtimex                    sys_old_adjtimex
304     common  swapoff                         sys_swapoff
305     common  getdents                        sys_getdents
306     common  create_module                   sys_ni_syscall
307     common  init_module                     sys_init_module
308     common  delete_module                   sys_delete_module
309     common  get_kernel_syms                 sys_ni_syscall
310     common  syslog                          sys_syslog
311     common  reboot                          sys_reboot
312     common  clone                           alpha_clone
313     common  uselib                          sys_uselib
314     common  mlock                           sys_mlock
315     common  munlock                         sys_munlock
316     common  mlockall                        sys_mlockall
317     common  munlockall                      sys_munlockall
318     common  sysinfo                         sys_sysinfo
319     common  _sysctl                         sys_ni_syscall
321     common  oldumount                       sys_oldumount
322     common  swapon                          sys_swapon
323     common  times                           sys_times
324     common  personality                     sys_personality
325     common  setfsuid                        sys_setfsuid
326     common  setfsgid                        sys_setfsgid
327     common  ustat                           sys_ustat
328     common  statfs                          sys_statfs
329     common  fstatfs                         sys_fstatfs
330     common  sched_setparam                  sys_sched_setparam
331     common  sched_getparam                  sys_sched_getparam
332     common  sched_setscheduler              sys_sched_setscheduler
333     common  sched_getscheduler              sys_sched_getscheduler
334     common  sched_yield                     sys_sched_yield
335     common  sched_get_priority_max          sys_sched_get_priority_max
336     common  sched_get_priority_min          sys_sched_get_priority_min
337     common  sched_rr_get_interval           sys_sched_rr_get_interval
338     common  afs_syscall                     sys_ni_syscall
339     common  uname                           sys_newuname
340     common  nanosleep                       sys_nanosleep
341     common  mremap                          sys_mremap
342     common  nfsservctl                      sys_ni_syscall
343     common  setresuid                       sys_setresuid
344     common  getresuid                       sys_getresuid
345     common  pciconfig_read                  sys_pciconfig_read
346     common  pciconfig_write                 sys_pciconfig_write
347     common  query_module                    sys_ni_syscall
348     common  prctl                           sys_prctl
349     common  pread64                         sys_pread64
350     common  pwrite64                        sys_pwrite64
351     common  rt_sigreturn                    sys_rt_sigreturn
352     common  rt_sigaction                    sys_rt_sigaction
353     common  rt_sigprocmask                  sys_rt_sigprocmask
354     common  rt_sigpending                   sys_rt_sigpending
355     common  rt_sigtimedwait                 sys_rt_sigtimedwait
356     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
357     common  rt_sigsuspend                   sys_rt_sigsuspend
358     common  select                          sys_select
359     common  gettimeofday                    sys_gettimeofday
360     common  settimeofday                    sys_settimeofday
361     common  getitimer                       sys_getitimer
362     common  setitimer                       sys_setitimer
363     common  utimes                          sys_utimes
364     common  getrusage                       sys_getrusage
365     common  wait4                           sys_wait4
366     common  adjtimex                        sys_adjtimex
367     common  getcwd                          sys_getcwd
368     common  capget                          sys_capget
369     common  capset                          sys_capset
370     common  sendfile                        sys_sendfile64
371     common  setresgid                       sys_setresgid
372     common  getresgid                       sys_getresgid
373     common  dipc                            sys_ni_syscall
374     common  pivot_root                      sys_pivot_root
375     common  mincore                         sys_mincore
376     common  pciconfig_iobase                sys_pciconfig_iobase
377     common  getdents64                      sys_getdents64
378     common  gettid                          sys_gettid
379     common  readahead                       sys_readahead
381     common  tkill                           sys_tkill
382     common  setxattr                        sys_setxattr
383     common  lsetxattr                       sys_lsetxattr
384     common  fsetxattr                       sys_fsetxattr
385     common  getxattr                        sys_getxattr
386     common  lgetxattr                       sys_lgetxattr
387     common  fgetxattr                       sys_fgetxattr
388     common  listxattr                       sys_listxattr
389     common  llistxattr                      sys_llistxattr
390     common  flistxattr                      sys_flistxattr
391     common  removexattr                     sys_removexattr
392     common  lremovexattr                    sys_lremovexattr
393     common  fremovexattr                    sys_fremovexattr
394     common  futex                           sys_futex
395     common  sched_setaffinity               sys_sched_setaffinity
396     common  sched_getaffinity               sys_sched_getaffinity
397     common  tuxcall                         sys_ni_syscall
398     common  io_setup                        sys_io_setup
399     common  io_destroy                      sys_io_destroy
400     common  io_getevents                    sys_io_getevents
401     common  io_submit                       sys_io_submit
402     common  io_cancel                       sys_io_cancel
405     common  exit_group                      sys_exit_group
406     common  lookup_dcookie                  sys_ni_syscall
407     common  epoll_create                    sys_epoll_create
408     common  epoll_ctl                       sys_epoll_ctl
409     common  epoll_wait                      sys_epoll_wait
410     common  remap_file_pages                sys_remap_file_pages
411     common  set_tid_address                 sys_set_tid_address
412     common  restart_syscall                 sys_restart_syscall
413     common  fadvise64                       sys_fadvise64
414     common  timer_create                    sys_timer_create
415     common  timer_settime                   sys_timer_settime
416     common  timer_gettime                   sys_timer_gettime
417     common  timer_getoverrun                sys_timer_getoverrun
418     common  timer_delete                    sys_timer_delete
419     common  clock_settime                   sys_clock_settime
420     common  clock_gettime                   sys_clock_gettime
421     common  clock_getres                    sys_clock_getres
422     common  clock_nanosleep                 sys_clock_nanosleep
423     common  semtimedop                      sys_semtimedop
424     common  tgkill                          sys_tgkill
425     common  stat64                          sys_stat64
426     common  lstat64                         sys_lstat64
427     common  fstat64                         sys_fstat64
428     common  vserver                         sys_ni_syscall
429     common  mbind                           sys_ni_syscall
430     common  get_mempolicy                   sys_ni_syscall
431     common  set_mempolicy                   sys_ni_syscall
432     common  mq_open                         sys_mq_open
433     common  mq_unlink                       sys_mq_unlink
434     common  mq_timedsend                    sys_mq_timedsend
435     common  mq_timedreceive                 sys_mq_timedreceive
436     common  mq_notify                       sys_mq_notify
437     common  mq_getsetattr                   sys_mq_getsetattr
438     common  waitid                          sys_waitid
439     common  add_key                         sys_add_key
440     common  request_key                     sys_request_key
441     common  keyctl                          sys_keyctl
442     common  ioprio_set                      sys_ioprio_set
443     common  ioprio_get                      sys_ioprio_get
444     common  inotify_init                    sys_inotify_init
445     common  inotify_add_watch               sys_inotify_add_watch
446     common  inotify_rm_watch                sys_inotify_rm_watch
447     common  fdatasync                       sys_fdatasync
448     common  kexec_load                      sys_kexec_load
449     common  migrate_pages                   sys_migrate_pages
450     common  openat                          sys_openat
451     common  mkdirat                         sys_mkdirat
452     common  mknodat                         sys_mknodat
453     common  fchownat                        sys_fchownat
454     common  futimesat                       sys_futimesat
455     common  fstatat64                       sys_fstatat64
456     common  unlinkat                        sys_unlinkat
457     common  renameat                        sys_renameat
458     common  linkat                          sys_linkat
459     common  symlinkat                       sys_symlinkat
460     common  readlinkat                      sys_readlinkat
461     common  fchmodat                        sys_fchmodat
462     common  faccessat                       sys_faccessat
463     common  pselect6                        sys_pselect6
464     common  ppoll                           sys_ppoll
465     common  unshare                         sys_unshare
466     common  set_robust_list                 sys_set_robust_list
467     common  get_robust_list                 sys_get_robust_list
468     common  splice                          sys_splice
469     common  sync_file_range                 sys_sync_file_range
470     common  tee                             sys_tee
471     common  vmsplice                        sys_vmsplice
472     common  move_pages                      sys_move_pages
473     common  getcpu                          sys_getcpu
474     common  epoll_pwait                     sys_epoll_pwait
475     common  utimensat                       sys_utimensat
476     common  signalfd                        sys_signalfd
477     common  timerfd                         sys_ni_syscall
478     common  eventfd                         sys_eventfd
479     common  recvmmsg                        sys_recvmmsg
480     common  fallocate                       sys_fallocate
481     common  timerfd_create                  sys_timerfd_create
482     common  timerfd_settime                 sys_timerfd_settime
483     common  timerfd_gettime                 sys_timerfd_gettime
484     common  signalfd4                       sys_signalfd4
485     common  eventfd2                        sys_eventfd2
486     common  epoll_create1                   sys_epoll_create1
487     common  dup3                            sys_dup3
488     common  pipe2                           sys_pipe2
489     common  inotify_init1                   sys_inotify_init1
490     common  preadv                          sys_preadv
491     common  pwritev                         sys_pwritev
492     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
493     common  perf_event_open                 sys_perf_event_open
494     common  fanotify_init                   sys_fanotify_init
495     common  fanotify_mark                   sys_fanotify_mark
496     common  prlimit64                       sys_prlimit64
497     common  name_to_handle_at               sys_name_to_handle_at
498     common  open_by_handle_at               sys_open_by_handle_at
499     common  clock_adjtime                   sys_clock_adjtime
500     common  syncfs                          sys_syncfs
501     common  setns                           sys_setns
502     common  accept4                         sys_accept4
503     common  sendmmsg                        sys_sendmmsg
504     common  process_vm_readv                sys_process_vm_readv
505     common  process_vm_writev               sys_process_vm_writev
506     common  kcmp                            sys_kcmp
507     common  finit_module                    sys_finit_module
508     common  sched_setattr                   sys_sched_setattr
509     common  sched_getattr                   sys_sched_getattr
510     common  renameat2                       sys_renameat2
511     common  getrandom                       sys_getrandom
512     common  memfd_create                    sys_memfd_create
513     common  execveat                        sys_execveat
514     common  seccomp                         sys_seccomp
515     common  bpf                             sys_bpf
516     common  userfaultfd                     sys_userfaultfd
517     common  membarrier                      sys_membarrier
518     common  mlock2                          sys_mlock2
519     common  copy_file_range                 sys_copy_file_range
520     common  preadv2                         sys_preadv2
521     common  pwritev2                        sys_pwritev2
522     common  statx                           sys_statx
523     common  io_pgetevents                   sys_io_pgetevents
524     common  pkey_mprotect                   sys_pkey_mprotect
525     common  pkey_alloc                      sys_pkey_alloc
526     common  pkey_free                       sys_pkey_free
527     common  rseq                            sys_rseq
528     common  statfs64                        sys_statfs64
529     common  fstatfs64                       sys_fstatfs64
530     common  getegid                         sys_getegid
531     common  geteuid                         sys_geteuid
532     common  getppid                         sys_getppid
534     common  pidfd_send_signal               sys_pidfd_send_signal
535     common  io_uring_setup                  sys_io_uring_setup
536     common  io_uring_enter                  sys_io_uring_enter
537     common  io_uring_register               sys_io_uring_register
538     common  open_tree                       sys_open_tree
539     common  move_mount                      sys_move_mount
540     common  fsopen                          sys_fsopen
541     common  fsconfig                        sys_fsconfig
542     common  fsmount                         sys_fsmount
543     common  fspick                          sys_fspick
544     common  pidfd_open                      sys_pidfd_open
545     common  clone3                          alpha_clone3
546     common  close_range                     sys_close_range
547     common  openat2                         sys_openat2
548     common  pidfd_getfd                     sys_pidfd_getfd
549     common  faccessat2                      sys_faccessat2
550     common  process_madvise                 sys_process_madvise
551     common  epoll_pwait2                    sys_epoll_pwait2
552     common  mount_setattr                   sys_mount_setattr
553     common  quotactl_fd                     sys_quotactl_fd
554     common  landlock_create_ruleset         sys_landlock_create_ruleset
555     common  landlock_add_rule               sys_landlock_add_rule
556     common  landlock_restrict_self          sys_landlock_restrict_self
558     common  process_mrelease                sys_process_mrelease
559     common  futex_waitv                     sys_futex_waitv
560     common  set_mempolicy_home_node         sys_ni_syscall
561     common  cachestat                       sys_cachestat
562     common  fchmodat2                       sys_fchmodat2
563     common  map_shadow_stack                sys_map_shadow_stack
564     common  futex_wake                      sys_futex_wake
565     common  futex_wait                      sys_futex_wait
566     common  futex_requeue                   sys_futex_requeue
567     common  statmount                       sys_statmount
568     common  listmount                       sys_listmount
569     common  lsm_get_self_attr               sys_lsm_get_self_attr
570     common  lsm_set_self_attr               sys_lsm_set_self_attr
571     common  lsm_list_modules                sys_lsm_list_modules
572     common  mseal                           sys_mseal
573     common  setxattrat                      sys_setxattrat
574     common  getxattrat                      sys_getxattrat
575     common  listxattrat                     sys_listxattrat
576     common  removexattrat                   sys_removexattrat
577     common  open_tree_attr                  sys_open_tree_attr
578     common  file_getattr                    sys_file_getattr
579     common  file_setattr                    sys_file_setattr
580     common  listns                          sys_listns
581     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# HPPA
# - arch/parisc/kernel/syscalls/syscall.tbl
hppa_syscall_tbl = """
0       common  restart_syscall         sys_restart_syscall
1       common  exit                    sys_exit
2       common  fork                    sys_fork_wrapper
3       common  read                    sys_read
4       common  write                   sys_write
5       common  open                    sys_open                        compat_sys_open
6       common  close                   sys_close
7       common  waitpid                 sys_waitpid
8       common  creat                   sys_creat
9       common  link                    sys_link
10      common  unlink                  sys_unlink
11      common  execve                  sys_execve                      compat_sys_execve
12      common  chdir                   sys_chdir
13      32      time                    sys_time32
13      64      time                    sys_time
14      common  mknod                   sys_mknod
15      common  chmod                   sys_chmod
16      common  lchown                  sys_lchown
17      common  socket                  sys_socket
18      common  stat                    sys_newstat                     compat_sys_newstat
19      common  lseek                   sys_lseek                       compat_sys_lseek
20      common  getpid                  sys_getpid
21      common  mount                   sys_mount
22      common  bind                    sys_bind
23      common  setuid                  sys_setuid
24      common  getuid                  sys_getuid
25      32      stime                   sys_stime32
25      64      stime                   sys_stime
26      common  ptrace                  sys_ptrace                      compat_sys_ptrace
27      common  alarm                   sys_alarm
28      common  fstat                   sys_newfstat                    compat_sys_newfstat
29      common  pause                   sys_pause
30      32      utime                   sys_utime32
30      64      utime                   sys_utime
31      common  connect                 sys_connect
32      common  listen                  sys_listen
33      common  access                  sys_access
34      common  nice                    sys_nice
35      common  accept                  sys_accept
36      common  sync                    sys_sync
37      common  kill                    sys_kill
38      common  rename                  sys_rename
39      common  mkdir                   sys_mkdir
40      common  rmdir                   sys_rmdir
41      common  dup                     sys_dup
42      common  pipe                    sys_pipe
43      common  times                   sys_times                       compat_sys_times
44      common  getsockname             sys_getsockname
45      common  brk                     sys_brk
46      common  setgid                  sys_setgid
47      common  getgid                  sys_getgid
48      common  signal                  sys_signal
49      common  geteuid                 sys_geteuid
50      common  getegid                 sys_getegid
51      common  acct                    sys_acct
52      common  umount2                 sys_umount
53      common  getpeername             sys_getpeername
54      common  ioctl                   sys_ioctl                       compat_sys_ioctl
55      common  fcntl                   sys_fcntl                       compat_sys_fcntl
56      common  socketpair              sys_socketpair
57      common  setpgid                 sys_setpgid
58      common  send                    sys_send
59      common  uname                   sys_newuname
60      common  umask                   sys_umask
61      common  chroot                  sys_chroot
62      common  ustat                   sys_ustat                       compat_sys_ustat
63      common  dup2                    sys_dup2
64      common  getppid                 sys_getppid
65      common  getpgrp                 sys_getpgrp
66      common  setsid                  sys_setsid
67      common  pivot_root              sys_pivot_root
68      common  sgetmask                sys_sgetmask                    sys32_unimplemented
69      common  ssetmask                sys_ssetmask                    sys32_unimplemented
70      common  setreuid                sys_setreuid
71      common  setregid                sys_setregid
72      common  mincore                 sys_mincore
73      common  sigpending              sys_sigpending                  compat_sys_sigpending
74      common  sethostname             sys_sethostname
75      common  setrlimit               sys_setrlimit                   compat_sys_setrlimit
76      common  getrlimit               sys_getrlimit                   compat_sys_getrlimit
77      common  getrusage               sys_getrusage                   compat_sys_getrusage
78      common  gettimeofday            sys_gettimeofday                compat_sys_gettimeofday
79      common  settimeofday            sys_settimeofday                compat_sys_settimeofday
80      common  getgroups               sys_getgroups
81      common  setgroups               sys_setgroups
82      common  sendto                  sys_sendto
83      common  symlink                 sys_symlink
84      common  lstat                   sys_newlstat                    compat_sys_newlstat
85      common  readlink                sys_readlink
86      common  uselib                  sys_ni_syscall
87      common  swapon                  sys_swapon
88      common  reboot                  sys_reboot
89      common  mmap2                   sys_mmap2
90      common  mmap                    sys_mmap
91      common  munmap                  sys_munmap
92      common  truncate                sys_truncate                    compat_sys_truncate
93      common  ftruncate               sys_ftruncate                   compat_sys_ftruncate
94      common  fchmod                  sys_fchmod
95      common  fchown                  sys_fchown
96      common  getpriority             sys_getpriority
97      common  setpriority             sys_setpriority
98      common  recv                    sys_recv                        compat_sys_recv
99      common  statfs                  sys_statfs                      compat_sys_statfs
100     common  fstatfs                 sys_fstatfs                     compat_sys_fstatfs
101     common  stat64                  sys_stat64
103     common  syslog                  sys_syslog
104     common  setitimer               sys_setitimer                   compat_sys_setitimer
105     common  getitimer               sys_getitimer                   compat_sys_getitimer
106     common  capget                  sys_capget
107     common  capset                  sys_capset
108     32      pread64                 parisc_pread64
108     64      pread64                 sys_pread64
109     32      pwrite64                parisc_pwrite64
109     64      pwrite64                sys_pwrite64
110     common  getcwd                  sys_getcwd
111     common  vhangup                 sys_vhangup
112     common  fstat64                 sys_fstat64
113     common  vfork                   sys_vfork_wrapper
114     common  wait4                   sys_wait4                       compat_sys_wait4
115     common  swapoff                 sys_swapoff
116     common  sysinfo                 sys_sysinfo                     compat_sys_sysinfo
117     common  shutdown                sys_shutdown
118     common  fsync                   sys_fsync
119     common  madvise                 parisc_madvise
120     common  clone                   sys_clone_wrapper
121     common  setdomainname           sys_setdomainname
122     common  sendfile                sys_sendfile                    compat_sys_sendfile
123     common  recvfrom                sys_recvfrom                    compat_sys_recvfrom
124     32      adjtimex                sys_adjtimex_time32
124     64      adjtimex                sys_adjtimex
125     common  mprotect                sys_mprotect
126     common  sigprocmask             sys_sigprocmask                 compat_sys_sigprocmask
128     common  init_module             sys_init_module
129     common  delete_module           sys_delete_module
131     common  quotactl                sys_quotactl
132     common  getpgid                 sys_getpgid
133     common  fchdir                  sys_fchdir
134     common  bdflush                 sys_ni_syscall
135     common  sysfs                   sys_sysfs
136     32      personality             parisc_personality
136     64      personality             sys_personality
138     common  setfsuid                sys_setfsuid
139     common  setfsgid                sys_setfsgid
140     32      _llseek                 sys_llseek
141     common  getdents                sys_getdents                    compat_sys_getdents
142     common  _newselect              sys_select                      compat_sys_select
143     common  flock                   sys_flock
144     common  msync                   sys_msync
145     common  readv                   sys_readv
146     common  writev                  sys_writev
147     common  getsid                  sys_getsid
148     common  fdatasync               sys_fdatasync
149     common  _sysctl                 sys_ni_syscall
150     common  mlock                   sys_mlock
151     common  munlock                 sys_munlock
152     common  mlockall                sys_mlockall
153     common  munlockall              sys_munlockall
154     common  sched_setparam          sys_sched_setparam
155     common  sched_getparam          sys_sched_getparam
156     common  sched_setscheduler      sys_sched_setscheduler
157     common  sched_getscheduler      sys_sched_getscheduler
158     common  sched_yield             sys_sched_yield
159     common  sched_get_priority_max  sys_sched_get_priority_max
160     common  sched_get_priority_min  sys_sched_get_priority_min
161     32      sched_rr_get_interval   sys_sched_rr_get_interval_time32
161     64      sched_rr_get_interval   sys_sched_rr_get_interval
162     32      nanosleep               sys_nanosleep_time32
162     64      nanosleep               sys_nanosleep
163     common  mremap                  sys_mremap
164     common  setresuid               sys_setresuid
165     common  getresuid               sys_getresuid
166     common  sigaltstack             sys_sigaltstack                 compat_sys_sigaltstack
168     common  poll                    sys_poll
170     common  setresgid               sys_setresgid
171     common  getresgid               sys_getresgid
172     common  prctl                   sys_prctl
173     common  rt_sigreturn            sys_rt_sigreturn_wrapper
174     common  rt_sigaction            sys_rt_sigaction                compat_sys_rt_sigaction
175     common  rt_sigprocmask          sys_rt_sigprocmask              compat_sys_rt_sigprocmask
176     common  rt_sigpending           sys_rt_sigpending               compat_sys_rt_sigpending
177     32      rt_sigtimedwait         sys_rt_sigtimedwait_time32      compat_sys_rt_sigtimedwait_time32
177     64      rt_sigtimedwait         sys_rt_sigtimedwait
178     common  rt_sigqueueinfo         sys_rt_sigqueueinfo             compat_sys_rt_sigqueueinfo
179     common  rt_sigsuspend           sys_rt_sigsuspend               compat_sys_rt_sigsuspend
180     common  chown                   sys_chown
181     common  setsockopt              sys_setsockopt                  sys_setsockopt
182     common  getsockopt              sys_getsockopt                  sys_getsockopt
183     common  sendmsg                 sys_sendmsg                     compat_sys_sendmsg
184     common  recvmsg                 sys_recvmsg                     compat_sys_recvmsg
185     common  semop                   sys_semop
186     common  semget                  sys_semget
187     common  semctl                  sys_semctl                      compat_sys_semctl
188     common  msgsnd                  sys_msgsnd                      compat_sys_msgsnd
189     common  msgrcv                  sys_msgrcv                      compat_sys_msgrcv
190     common  msgget                  sys_msgget
191     common  msgctl                  sys_msgctl                      compat_sys_msgctl
192     common  shmat                   sys_shmat                       compat_sys_shmat
193     common  shmdt                   sys_shmdt
194     common  shmget                  sys_shmget
195     common  shmctl                  sys_shmctl                      compat_sys_shmctl
198     common  lstat64                 sys_lstat64
199     32      truncate64              parisc_truncate64
199     64      truncate64              sys_truncate64
200     32      ftruncate64             parisc_ftruncate64
200     64      ftruncate64             sys_ftruncate64
201     common  getdents64              sys_getdents64
202     common  fcntl64                 sys_fcntl64                     compat_sys_fcntl64
206     common  gettid                  sys_gettid
207     32      readahead               parisc_readahead
207     64      readahead               sys_readahead
208     common  tkill                   sys_tkill
209     common  sendfile64              sys_sendfile64                  compat_sys_sendfile64
210     32      futex                   sys_futex_time32
210     64      futex                   sys_futex
211     common  sched_setaffinity       sys_sched_setaffinity           compat_sys_sched_setaffinity
212     common  sched_getaffinity       sys_sched_getaffinity           compat_sys_sched_getaffinity
215     common  io_setup                sys_io_setup                    compat_sys_io_setup
216     common  io_destroy              sys_io_destroy
217     32      io_getevents            sys_io_getevents_time32
217     64      io_getevents            sys_io_getevents
218     common  io_submit               sys_io_submit                   compat_sys_io_submit
219     common  io_cancel               sys_io_cancel
222     common  exit_group              sys_exit_group
223     common  lookup_dcookie          sys_ni_syscall
224     common  epoll_create            sys_epoll_create
225     common  epoll_ctl               sys_epoll_ctl
226     common  epoll_wait              sys_epoll_wait
227     common  remap_file_pages        sys_remap_file_pages
228     32      semtimedop              sys_semtimedop_time32
228     64      semtimedop              sys_semtimedop
229     common  mq_open                 sys_mq_open                     compat_sys_mq_open
230     common  mq_unlink               sys_mq_unlink
231     32      mq_timedsend            sys_mq_timedsend_time32
231     64      mq_timedsend            sys_mq_timedsend
232     32      mq_timedreceive         sys_mq_timedreceive_time32
232     64      mq_timedreceive         sys_mq_timedreceive
233     common  mq_notify               sys_mq_notify                   compat_sys_mq_notify
234     common  mq_getsetattr           sys_mq_getsetattr               compat_sys_mq_getsetattr
235     common  waitid                  sys_waitid                      compat_sys_waitid
236     32      fadvise64_64            parisc_fadvise64_64
236     64      fadvise64_64            sys_fadvise64_64
237     common  set_tid_address         sys_set_tid_address
238     common  setxattr                sys_setxattr
239     common  lsetxattr               sys_lsetxattr
240     common  fsetxattr               sys_fsetxattr
241     common  getxattr                sys_getxattr
242     common  lgetxattr               sys_lgetxattr
243     common  fgetxattr               sys_fgetxattr
244     common  listxattr               sys_listxattr
245     common  llistxattr              sys_llistxattr
246     common  flistxattr              sys_flistxattr
247     common  removexattr             sys_removexattr
248     common  lremovexattr            sys_lremovexattr
249     common  fremovexattr            sys_fremovexattr
250     common  timer_create            sys_timer_create                compat_sys_timer_create
251     32      timer_settime           sys_timer_settime32
251     64      timer_settime           sys_timer_settime
252     32      timer_gettime           sys_timer_gettime32
252     64      timer_gettime           sys_timer_gettime
253     common  timer_getoverrun        sys_timer_getoverrun
254     common  timer_delete            sys_timer_delete
255     32      clock_settime           sys_clock_settime32
255     64      clock_settime           sys_clock_settime
256     32      clock_gettime           sys_clock_gettime32
256     64      clock_gettime           sys_clock_gettime
257     32      clock_getres            sys_clock_getres_time32
257     64      clock_getres            sys_clock_getres
258     32      clock_nanosleep         sys_clock_nanosleep_time32
258     64      clock_nanosleep         sys_clock_nanosleep
259     common  tgkill                  sys_tgkill
260     common  mbind                   sys_mbind
261     common  get_mempolicy           sys_get_mempolicy
262     common  set_mempolicy           sys_set_mempolicy
264     common  add_key                 sys_add_key
265     common  request_key             sys_request_key
266     common  keyctl                  sys_keyctl                      compat_sys_keyctl
267     common  ioprio_set              sys_ioprio_set
268     common  ioprio_get              sys_ioprio_get
269     common  inotify_init            sys_inotify_init
270     common  inotify_add_watch       sys_inotify_add_watch
271     common  inotify_rm_watch        sys_inotify_rm_watch
272     common  migrate_pages           sys_migrate_pages
273     32      pselect6                sys_pselect6_time32             compat_sys_pselect6_time32
273     64      pselect6                sys_pselect6
274     32      ppoll                   sys_ppoll_time32                compat_sys_ppoll_time32
274     64      ppoll                   sys_ppoll
275     common  openat                  sys_openat                      compat_sys_openat
276     common  mkdirat                 sys_mkdirat
277     common  mknodat                 sys_mknodat
278     common  fchownat                sys_fchownat
279     32      futimesat               sys_futimesat_time32
279     64      futimesat               sys_futimesat
280     common  fstatat64               sys_fstatat64
281     common  unlinkat                sys_unlinkat
282     common  renameat                sys_renameat
283     common  linkat                  sys_linkat
284     common  symlinkat               sys_symlinkat
285     common  readlinkat              sys_readlinkat
286     common  fchmodat                sys_fchmodat
287     common  faccessat               sys_faccessat
288     common  unshare                 sys_unshare
289     common  set_robust_list         sys_set_robust_list             compat_sys_set_robust_list
290     common  get_robust_list         sys_get_robust_list             compat_sys_get_robust_list
291     common  splice                  sys_splice
292     32      sync_file_range         parisc_sync_file_range
292     64      sync_file_range         sys_sync_file_range
293     common  tee                     sys_tee
294     common  vmsplice                sys_vmsplice
295     common  move_pages              sys_move_pages
296     common  getcpu                  sys_getcpu
297     common  epoll_pwait             sys_epoll_pwait                 compat_sys_epoll_pwait
298     common  statfs64                sys_statfs64                    compat_sys_statfs64
299     common  fstatfs64               sys_fstatfs64                   compat_sys_fstatfs64
300     common  kexec_load              sys_kexec_load                  compat_sys_kexec_load
301     32      utimensat               sys_utimensat_time32
301     64      utimensat               sys_utimensat
302     common  signalfd                sys_signalfd                    compat_sys_signalfd
304     common  eventfd                 sys_eventfd
305     32      fallocate               parisc_fallocate
305     64      fallocate               sys_fallocate
306     common  timerfd_create          parisc_timerfd_create
307     32      timerfd_settime         sys_timerfd_settime32
307     64      timerfd_settime         sys_timerfd_settime
308     32      timerfd_gettime         sys_timerfd_gettime32
308     64      timerfd_gettime         sys_timerfd_gettime
309     common  signalfd4               parisc_signalfd4                parisc_compat_signalfd4
310     common  eventfd2                parisc_eventfd2
311     common  epoll_create1           sys_epoll_create1
312     common  dup3                    sys_dup3
313     common  pipe2                   parisc_pipe2
314     common  inotify_init1           parisc_inotify_init1
315     common  preadv  sys_preadv      compat_sys_preadv
316     common  pwritev sys_pwritev     compat_sys_pwritev
317     common  rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo           compat_sys_rt_tgsigqueueinfo
318     common  perf_event_open         sys_perf_event_open
319     32      recvmmsg                sys_recvmmsg_time32             compat_sys_recvmmsg_time32
319     64      recvmmsg                sys_recvmmsg
320     common  accept4                 sys_accept4
321     common  prlimit64               sys_prlimit64
322     common  fanotify_init           sys_fanotify_init
323     common  fanotify_mark           sys_fanotify_mark               compat_sys_fanotify_mark
324     32      clock_adjtime           sys_clock_adjtime32
324     64      clock_adjtime           sys_clock_adjtime
325     common  name_to_handle_at       sys_name_to_handle_at
326     common  open_by_handle_at       sys_open_by_handle_at           compat_sys_open_by_handle_at
327     common  syncfs                  sys_syncfs
328     common  setns                   sys_setns
329     common  sendmmsg                sys_sendmmsg                    compat_sys_sendmmsg
330     common  process_vm_readv        sys_process_vm_readv
331     common  process_vm_writev       sys_process_vm_writev
332     common  kcmp                    sys_kcmp
333     common  finit_module            sys_finit_module
334     common  sched_setattr           sys_sched_setattr
335     common  sched_getattr           sys_sched_getattr
336     32      utimes                  sys_utimes_time32
336     64      utimes                  sys_utimes
337     common  renameat2               sys_renameat2
338     common  seccomp                 sys_seccomp
339     common  getrandom               sys_getrandom
340     common  memfd_create            sys_memfd_create
341     common  bpf                     sys_bpf
342     common  execveat                sys_execveat                    compat_sys_execveat
343     common  membarrier              sys_membarrier
344     common  userfaultfd             parisc_userfaultfd
345     common  mlock2                  sys_mlock2
346     common  copy_file_range         sys_copy_file_range
347     common  preadv2                 sys_preadv2                     compat_sys_preadv2
348     common  pwritev2                sys_pwritev2                    compat_sys_pwritev2
349     common  statx                   sys_statx
350     32      io_pgetevents           sys_io_pgetevents_time32        compat_sys_io_pgetevents
350     64      io_pgetevents           sys_io_pgetevents
351     common  pkey_mprotect           sys_pkey_mprotect
352     common  pkey_alloc              sys_pkey_alloc
353     common  pkey_free               sys_pkey_free
354     common  rseq                    sys_rseq
355     common  kexec_file_load         sys_kexec_file_load             sys_kexec_file_load
356     common  cacheflush              sys_cacheflush
403     32      clock_gettime64                 sys_clock_gettime               sys_clock_gettime
404     32      clock_settime64                 sys_clock_settime               sys_clock_settime
405     32      clock_adjtime64                 sys_clock_adjtime               sys_clock_adjtime
406     32      clock_getres_time64             sys_clock_getres                sys_clock_getres
407     32      clock_nanosleep_time64          sys_clock_nanosleep             sys_clock_nanosleep
408     32      timer_gettime64                 sys_timer_gettime               sys_timer_gettime
409     32      timer_settime64                 sys_timer_settime               sys_timer_settime
410     32      timerfd_gettime64               sys_timerfd_gettime             sys_timerfd_gettime
411     32      timerfd_settime64               sys_timerfd_settime             sys_timerfd_settime
412     32      utimensat_time64                sys_utimensat                   sys_utimensat
413     32      pselect6_time64                 sys_pselect6                    compat_sys_pselect6_time64
414     32      ppoll_time64                    sys_ppoll                       compat_sys_ppoll_time64
416     32      io_pgetevents_time64            sys_io_pgetevents               compat_sys_io_pgetevents_time64
417     32      recvmmsg_time64                 sys_recvmmsg                    compat_sys_recvmmsg_time64
418     32      mq_timedsend_time64             sys_mq_timedsend                sys_mq_timedsend
419     32      mq_timedreceive_time64          sys_mq_timedreceive             sys_mq_timedreceive
420     32      semtimedop_time64               sys_semtimedop                  sys_semtimedop
421     32      rt_sigtimedwait_time64          sys_rt_sigtimedwait             compat_sys_rt_sigtimedwait_time64
422     32      futex_time64                    sys_futex                       sys_futex
423     32      sched_rr_get_interval_time64    sys_sched_rr_get_interval       sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3_wrapper
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2                compat_sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# OpenRISC
or1k_syscall_tbl = arm64_syscall_tbl


# Nios II
nios2_syscall_tbl = arm64_syscall_tbl


# MicroBlaze
# - arch/microblaze/kernel/syscalls/syscall.tbl
microblaze_syscall_tbl = """
0       common  restart_syscall                 sys_restart_syscall
1       common  exit                            sys_exit
2       common  fork                            sys_fork
3       common  read                            sys_read
4       common  write                           sys_write
5       common  open                            sys_open
6       common  close                           sys_close
7       common  waitpid                         sys_waitpid
8       common  creat                           sys_creat
9       common  link                            sys_link
10      common  unlink                          sys_unlink
11      common  execve                          sys_execve
12      common  chdir                           sys_chdir
13      common  time                            sys_time32
14      common  mknod                           sys_mknod
15      common  chmod                           sys_chmod
16      common  lchown                          sys_lchown
17      common  break                           sys_ni_syscall
18      common  oldstat                         sys_ni_syscall
19      common  lseek                           sys_lseek
20      common  getpid                          sys_getpid
21      common  mount                           sys_mount
22      common  umount                          sys_oldumount
23      common  setuid                          sys_setuid
24      common  getuid                          sys_getuid
25      common  stime                           sys_stime32
26      common  ptrace                          sys_ptrace
27      common  alarm                           sys_alarm
28      common  oldfstat                        sys_ni_syscall
29      common  pause                           sys_pause
30      common  utime                           sys_utime32
31      common  stty                            sys_ni_syscall
32      common  gtty                            sys_ni_syscall
33      common  access                          sys_access
34      common  nice                            sys_nice
35      common  ftime                           sys_ni_syscall
36      common  sync                            sys_sync
37      common  kill                            sys_kill
38      common  rename                          sys_rename
39      common  mkdir                           sys_mkdir
40      common  rmdir                           sys_rmdir
41      common  dup                             sys_dup
42      common  pipe                            sys_pipe
43      common  times                           sys_times
44      common  prof                            sys_ni_syscall
45      common  brk                             sys_brk
46      common  setgid                          sys_setgid
47      common  getgid                          sys_getgid
48      common  signal                          sys_signal
49      common  geteuid                         sys_geteuid
50      common  getegid                         sys_getegid
51      common  acct                            sys_acct
52      common  umount2                         sys_umount
53      common  lock                            sys_ni_syscall
54      common  ioctl                           sys_ioctl
55      common  fcntl                           sys_fcntl
56      common  mpx                             sys_ni_syscall
57      common  setpgid                         sys_setpgid
58      common  ulimit                          sys_ni_syscall
59      common  oldolduname                     sys_ni_syscall
60      common  umask                           sys_umask
61      common  chroot                          sys_chroot
62      common  ustat                           sys_ustat
63      common  dup2                            sys_dup2
64      common  getppid                         sys_getppid
65      common  getpgrp                         sys_getpgrp
66      common  setsid                          sys_setsid
67      common  sigaction                       sys_ni_syscall
68      common  sgetmask                        sys_sgetmask
69      common  ssetmask                        sys_ssetmask
70      common  setreuid                        sys_setreuid
71      common  setregid                        sys_setregid
72      common  sigsuspend                      sys_ni_syscall
73      common  sigpending                      sys_sigpending
74      common  sethostname                     sys_sethostname
75      common  setrlimit                       sys_setrlimit
76      common  getrlimit                       sys_ni_syscall
77      common  getrusage                       sys_getrusage
78      common  gettimeofday                    sys_gettimeofday
79      common  settimeofday                    sys_settimeofday
80      common  getgroups                       sys_getgroups
81      common  setgroups                       sys_setgroups
82      common  select                          sys_ni_syscall
83      common  symlink                         sys_symlink
84      common  oldlstat                        sys_ni_syscall
85      common  readlink                        sys_readlink
86      common  uselib                          sys_uselib
87      common  swapon                          sys_swapon
88      common  reboot                          sys_reboot
89      common  readdir                         sys_ni_syscall
90      common  mmap                            sys_mmap
91      common  munmap                          sys_munmap
92      common  truncate                        sys_truncate
93      common  ftruncate                       sys_ftruncate
94      common  fchmod                          sys_fchmod
95      common  fchown                          sys_fchown
96      common  getpriority                     sys_getpriority
97      common  setpriority                     sys_setpriority
98      common  profil                          sys_ni_syscall
99      common  statfs                          sys_statfs
100     common  fstatfs                         sys_fstatfs
101     common  ioperm                          sys_ni_syscall
102     common  socketcall                      sys_socketcall
103     common  syslog                          sys_syslog
104     common  setitimer                       sys_setitimer
105     common  getitimer                       sys_getitimer
106     common  stat                            sys_newstat
107     common  lstat                           sys_newlstat
108     common  fstat                           sys_newfstat
109     common  olduname                        sys_ni_syscall
110     common  iopl                            sys_ni_syscall
111     common  vhangup                         sys_vhangup
112     common  idle                            sys_ni_syscall
113     common  vm86old                         sys_ni_syscall
114     common  wait4                           sys_wait4
115     common  swapoff                         sys_swapoff
116     common  sysinfo                         sys_sysinfo
117     common  ipc                             sys_ni_syscall
118     common  fsync                           sys_fsync
119     common  sigreturn                       sys_ni_syscall
120     common  clone                           sys_clone
121     common  setdomainname                   sys_setdomainname
122     common  uname                           sys_newuname
123     common  modify_ldt                      sys_ni_syscall
124     common  adjtimex                        sys_adjtimex_time32
125     common  mprotect                        sys_mprotect
126     common  sigprocmask                     sys_sigprocmask
127     common  create_module                   sys_ni_syscall
128     common  init_module                     sys_init_module
129     common  delete_module                   sys_delete_module
130     common  get_kernel_syms                 sys_ni_syscall
131     common  quotactl                        sys_quotactl
132     common  getpgid                         sys_getpgid
133     common  fchdir                          sys_fchdir
134     common  bdflush                         sys_ni_syscall
135     common  sysfs                           sys_sysfs
136     common  personality                     sys_personality
137     common  afs_syscall                     sys_ni_syscall
138     common  setfsuid                        sys_setfsuid
139     common  setfsgid                        sys_setfsgid
140     common  _llseek                         sys_llseek
141     common  getdents                        sys_getdents
142     common  _newselect                      sys_select
143     common  flock                           sys_flock
144     common  msync                           sys_msync
145     common  readv                           sys_readv
146     common  writev                          sys_writev
147     common  getsid                          sys_getsid
148     common  fdatasync                       sys_fdatasync
149     common  _sysctl                         sys_ni_syscall
150     common  mlock                           sys_mlock
151     common  munlock                         sys_munlock
152     common  mlockall                        sys_mlockall
153     common  munlockall                      sys_munlockall
154     common  sched_setparam                  sys_sched_setparam
155     common  sched_getparam                  sys_sched_getparam
156     common  sched_setscheduler              sys_sched_setscheduler
157     common  sched_getscheduler              sys_sched_getscheduler
158     common  sched_yield                     sys_sched_yield
159     common  sched_get_priority_max          sys_sched_get_priority_max
160     common  sched_get_priority_min          sys_sched_get_priority_min
161     common  sched_rr_get_interval           sys_sched_rr_get_interval_time32
162     common  nanosleep                       sys_nanosleep_time32
163     common  mremap                          sys_mremap
164     common  setresuid                       sys_setresuid
165     common  getresuid                       sys_getresuid
166     common  vm86                            sys_ni_syscall
167     common  query_module                    sys_ni_syscall
168     common  poll                            sys_poll
169     common  nfsservctl                      sys_ni_syscall
170     common  setresgid                       sys_setresgid
171     common  getresgid                       sys_getresgid
172     common  prctl                           sys_prctl
173     common  rt_sigreturn                    sys_rt_sigreturn_wrapper
174     common  rt_sigaction                    sys_rt_sigaction
175     common  rt_sigprocmask                  sys_rt_sigprocmask
176     common  rt_sigpending                   sys_rt_sigpending
177     common  rt_sigtimedwait                 sys_rt_sigtimedwait_time32
178     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
179     common  rt_sigsuspend                   sys_rt_sigsuspend
180     common  pread64                         sys_pread64
181     common  pwrite64                        sys_pwrite64
182     common  chown                           sys_chown
183     common  getcwd                          sys_getcwd
184     common  capget                          sys_capget
185     common  capset                          sys_capset
186     common  sigaltstack                     sys_ni_syscall
187     common  sendfile                        sys_sendfile
188     common  getpmsg                         sys_ni_syscall
189     common  putpmsg                         sys_ni_syscall
190     common  vfork                           sys_vfork
191     common  ugetrlimit                      sys_getrlimit
192     common  mmap2                           sys_mmap2
193     common  truncate64                      sys_truncate64
194     common  ftruncate64                     sys_ftruncate64
195     common  stat64                          sys_stat64
196     common  lstat64                         sys_lstat64
197     common  fstat64                         sys_fstat64
198     common  lchown32                        sys_lchown
199     common  getuid32                        sys_getuid
200     common  getgid32                        sys_getgid
201     common  geteuid32                       sys_geteuid
202     common  getegid32                       sys_getegid
203     common  setreuid32                      sys_setreuid
204     common  setregid32                      sys_setregid
205     common  getgroups32                     sys_getgroups
206     common  setgroups32                     sys_setgroups
207     common  fchown32                        sys_fchown
208     common  setresuid32                     sys_setresuid
209     common  getresuid32                     sys_getresuid
210     common  setresgid32                     sys_setresgid
211     common  getresgid32                     sys_getresgid
212     common  chown32                         sys_chown
213     common  setuid32                        sys_setuid
214     common  setgid32                        sys_setgid
215     common  setfsuid32                      sys_setfsuid
216     common  setfsgid32                      sys_setfsgid
217     common  pivot_root                      sys_pivot_root
218     common  mincore                         sys_mincore
219     common  madvise                         sys_madvise
220     common  getdents64                      sys_getdents64
221     common  fcntl64                         sys_fcntl64
224     common  gettid                          sys_gettid
225     common  readahead                       sys_readahead
226     common  setxattr                        sys_setxattr
227     common  lsetxattr                       sys_lsetxattr
228     common  fsetxattr                       sys_fsetxattr
229     common  getxattr                        sys_getxattr
230     common  lgetxattr                       sys_lgetxattr
231     common  fgetxattr                       sys_fgetxattr
232     common  listxattr                       sys_listxattr
233     common  llistxattr                      sys_llistxattr
234     common  flistxattr                      sys_flistxattr
235     common  removexattr                     sys_removexattr
236     common  lremovexattr                    sys_lremovexattr
237     common  fremovexattr                    sys_fremovexattr
238     common  tkill                           sys_tkill
239     common  sendfile64                      sys_sendfile64
240     common  futex                           sys_futex_time32
241     common  sched_setaffinity               sys_sched_setaffinity
242     common  sched_getaffinity               sys_sched_getaffinity
243     common  set_thread_area                 sys_ni_syscall
244     common  get_thread_area                 sys_ni_syscall
245     common  io_setup                        sys_io_setup
246     common  io_destroy                      sys_io_destroy
247     common  io_getevents                    sys_io_getevents_time32
248     common  io_submit                       sys_io_submit
249     common  io_cancel                       sys_io_cancel
250     common  fadvise64                       sys_fadvise64
252     common  exit_group                      sys_exit_group
253     common  lookup_dcookie                  sys_ni_syscall
254     common  epoll_create                    sys_epoll_create
255     common  epoll_ctl                       sys_epoll_ctl
256     common  epoll_wait                      sys_epoll_wait
257     common  remap_file_pages                sys_remap_file_pages
258     common  set_tid_address                 sys_set_tid_address
259     common  timer_create                    sys_timer_create
260     common  timer_settime                   sys_timer_settime32
261     common  timer_gettime                   sys_timer_gettime32
262     common  timer_getoverrun                sys_timer_getoverrun
263     common  timer_delete                    sys_timer_delete
264     common  clock_settime                   sys_clock_settime32
265     common  clock_gettime                   sys_clock_gettime32
266     common  clock_getres                    sys_clock_getres_time32
267     common  clock_nanosleep                 sys_clock_nanosleep_time32
268     common  statfs64                        sys_statfs64
269     common  fstatfs64                       sys_fstatfs64
270     common  tgkill                          sys_tgkill
271     common  utimes                          sys_utimes_time32
272     common  fadvise64_64                    sys_fadvise64_64
273     common  vserver                         sys_ni_syscall
274     common  mbind                           sys_mbind
275     common  get_mempolicy                   sys_get_mempolicy
276     common  set_mempolicy                   sys_set_mempolicy
277     common  mq_open                         sys_mq_open
278     common  mq_unlink                       sys_mq_unlink
279     common  mq_timedsend                    sys_mq_timedsend_time32
280     common  mq_timedreceive                 sys_mq_timedreceive_time32
281     common  mq_notify                       sys_mq_notify
282     common  mq_getsetattr                   sys_mq_getsetattr
283     common  kexec_load                      sys_kexec_load
284     common  waitid                          sys_waitid
286     common  add_key                         sys_add_key
287     common  request_key                     sys_request_key
288     common  keyctl                          sys_keyctl
289     common  ioprio_set                      sys_ioprio_set
290     common  ioprio_get                      sys_ioprio_get
291     common  inotify_init                    sys_inotify_init
292     common  inotify_add_watch               sys_inotify_add_watch
293     common  inotify_rm_watch                sys_inotify_rm_watch
294     common  migrate_pages                   sys_ni_syscall
295     common  openat                          sys_openat
296     common  mkdirat                         sys_mkdirat
297     common  mknodat                         sys_mknodat
298     common  fchownat                        sys_fchownat
299     common  futimesat                       sys_futimesat_time32
300     common  fstatat64                       sys_fstatat64
301     common  unlinkat                        sys_unlinkat
302     common  renameat                        sys_renameat
303     common  linkat                          sys_linkat
304     common  symlinkat                       sys_symlinkat
305     common  readlinkat                      sys_readlinkat
306     common  fchmodat                        sys_fchmodat
307     common  faccessat                       sys_faccessat
308     common  pselect6                        sys_pselect6_time32
309     common  ppoll                           sys_ppoll_time32
310     common  unshare                         sys_unshare
311     common  set_robust_list                 sys_set_robust_list
312     common  get_robust_list                 sys_get_robust_list
313     common  splice                          sys_splice
314     common  sync_file_range                 sys_sync_file_range
315     common  tee                             sys_tee
316     common  vmsplice                        sys_vmsplice
317     common  move_pages                      sys_move_pages
318     common  getcpu                          sys_getcpu
319     common  epoll_pwait                     sys_epoll_pwait
320     common  utimensat                       sys_utimensat_time32
321     common  signalfd                        sys_signalfd
322     common  timerfd_create                  sys_timerfd_create
323     common  eventfd                         sys_eventfd
324     common  fallocate                       sys_fallocate
325     common  semtimedop                      sys_semtimedop_time32
326     common  timerfd_settime                 sys_timerfd_settime32
327     common  timerfd_gettime                 sys_timerfd_gettime32
328     common  semctl                          sys_old_semctl
329     common  semget                          sys_semget
330     common  semop                           sys_semop
331     common  msgctl                          sys_old_msgctl
332     common  msgget                          sys_msgget
333     common  msgrcv                          sys_msgrcv
334     common  msgsnd                          sys_msgsnd
335     common  shmat                           sys_shmat
336     common  shmctl                          sys_old_shmctl
337     common  shmdt                           sys_shmdt
338     common  shmget                          sys_shmget
339     common  signalfd4                       sys_signalfd4
340     common  eventfd2                        sys_eventfd2
341     common  epoll_create1                   sys_epoll_create1
342     common  dup3                            sys_dup3
343     common  pipe2                           sys_pipe2
344     common  inotify_init1                   sys_inotify_init1
345     common  socket                          sys_socket
346     common  socketpair                      sys_socketpair
347     common  bind                            sys_bind
348     common  listen                          sys_listen
349     common  accept                          sys_accept
350     common  connect                         sys_connect
351     common  getsockname                     sys_getsockname
352     common  getpeername                     sys_getpeername
353     common  sendto                          sys_sendto
354     common  send                            sys_send
355     common  recvfrom                        sys_recvfrom
356     common  recv                            sys_recv
357     common  setsockopt                      sys_setsockopt
358     common  getsockopt                      sys_getsockopt
359     common  shutdown                        sys_shutdown
360     common  sendmsg                         sys_sendmsg
361     common  recvmsg                         sys_recvmsg
362     common  accept4                         sys_accept4
363     common  preadv                          sys_preadv
364     common  pwritev                         sys_pwritev
365     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
366     common  perf_event_open                 sys_perf_event_open
367     common  recvmmsg                        sys_recvmmsg_time32
368     common  fanotify_init                   sys_fanotify_init
369     common  fanotify_mark                   sys_fanotify_mark
370     common  prlimit64                       sys_prlimit64
371     common  name_to_handle_at               sys_name_to_handle_at
372     common  open_by_handle_at               sys_open_by_handle_at
373     common  clock_adjtime                   sys_clock_adjtime32
374     common  syncfs                          sys_syncfs
375     common  setns                           sys_setns
376     common  sendmmsg                        sys_sendmmsg
377     common  process_vm_readv                sys_process_vm_readv
378     common  process_vm_writev               sys_process_vm_writev
379     common  kcmp                            sys_kcmp
380     common  finit_module                    sys_finit_module
381     common  sched_setattr                   sys_sched_setattr
382     common  sched_getattr                   sys_sched_getattr
383     common  renameat2                       sys_renameat2
384     common  seccomp                         sys_seccomp
385     common  getrandom                       sys_getrandom
386     common  memfd_create                    sys_memfd_create
387     common  bpf                             sys_bpf
388     common  execveat                        sys_execveat
389     common  userfaultfd                     sys_userfaultfd
390     common  membarrier                      sys_membarrier
391     common  mlock2                          sys_mlock2
392     common  copy_file_range                 sys_copy_file_range
393     common  preadv2                         sys_preadv2
394     common  pwritev2                        sys_pwritev2
395     common  pkey_mprotect                   sys_pkey_mprotect
396     common  pkey_alloc                      sys_pkey_alloc
397     common  pkey_free                       sys_pkey_free
398     common  statx                           sys_statx
399     common  io_pgetevents                   sys_io_pgetevents_time32
400     common  rseq                            sys_rseq
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6
414     common  ppoll_time64                    sys_ppoll
416     common  io_pgetevents_time64            sys_io_pgetevents
417     common  recvmmsg_time64                 sys_recvmmsg
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# Xtensa
# arch/xtensa/kernel/syscalls/syscall.tbl
xtensa_syscall_tbl = """
0       common  spill                           sys_ni_syscall
1       common  xtensa                          sys_ni_syscall
2       common  available4                      sys_ni_syscall
3       common  available5                      sys_ni_syscall
4       common  available6                      sys_ni_syscall
5       common  available7                      sys_ni_syscall
6       common  available8                      sys_ni_syscall
7       common  available9                      sys_ni_syscall
8       common  open                            sys_open
9       common  close                           sys_close
10      common  dup                             sys_dup
11      common  dup2                            sys_dup2
12      common  read                            sys_read
13      common  write                           sys_write
14      common  select                          sys_select
15      common  lseek                           sys_lseek
16      common  poll                            sys_poll
17      common  _llseek                         sys_llseek
18      common  epoll_wait                      sys_epoll_wait
19      common  epoll_ctl                       sys_epoll_ctl
20      common  epoll_create                    sys_epoll_create
21      common  creat                           sys_creat
22      common  truncate                        sys_truncate
23      common  ftruncate                       sys_ftruncate
24      common  readv                           sys_readv
25      common  writev                          sys_writev
26      common  fsync                           sys_fsync
27      common  fdatasync                       sys_fdatasync
28      common  truncate64                      sys_truncate64
29      common  ftruncate64                     sys_ftruncate64
30      common  pread64                         sys_pread64
31      common  pwrite64                        sys_pwrite64
32      common  link                            sys_link
33      common  rename                          sys_rename
34      common  symlink                         sys_symlink
35      common  readlink                        sys_readlink
36      common  mknod                           sys_mknod
37      common  pipe                            sys_pipe
38      common  unlink                          sys_unlink
39      common  rmdir                           sys_rmdir
40      common  mkdir                           sys_mkdir
41      common  chdir                           sys_chdir
42      common  fchdir                          sys_fchdir
43      common  getcwd                          sys_getcwd
44      common  chmod                           sys_chmod
45      common  chown                           sys_chown
46      common  stat                            sys_newstat
47      common  stat64                          sys_stat64
48      common  lchown                          sys_lchown
49      common  lstat                           sys_newlstat
50      common  lstat64                         sys_lstat64
51      common  available51                     sys_ni_syscall
52      common  fchmod                          sys_fchmod
53      common  fchown                          sys_fchown
54      common  fstat                           sys_newfstat
55      common  fstat64                         sys_fstat64
56      common  flock                           sys_flock
57      common  access                          sys_access
58      common  umask                           sys_umask
59      common  getdents                        sys_getdents
60      common  getdents64                      sys_getdents64
61      common  fcntl64                         sys_fcntl64
62      common  fallocate                       sys_fallocate
63      common  fadvise64_64                    xtensa_fadvise64_64
64      common  utime                           sys_utime32
65      common  utimes                          sys_utimes_time32
66      common  ioctl                           sys_ioctl
67      common  fcntl                           sys_fcntl
68      common  setxattr                        sys_setxattr
69      common  getxattr                        sys_getxattr
70      common  listxattr                       sys_listxattr
71      common  removexattr                     sys_removexattr
72      common  lsetxattr                       sys_lsetxattr
73      common  lgetxattr                       sys_lgetxattr
74      common  llistxattr                      sys_llistxattr
75      common  lremovexattr                    sys_lremovexattr
76      common  fsetxattr                       sys_fsetxattr
77      common  fgetxattr                       sys_fgetxattr
78      common  flistxattr                      sys_flistxattr
79      common  fremovexattr                    sys_fremovexattr
80      common  mmap2                           sys_mmap_pgoff
81      common  munmap                          sys_munmap
82      common  mprotect                        sys_mprotect
83      common  brk                             sys_brk
84      common  mlock                           sys_mlock
85      common  munlock                         sys_munlock
86      common  mlockall                        sys_mlockall
87      common  munlockall                      sys_munlockall
88      common  mremap                          sys_mremap
89      common  msync                           sys_msync
90      common  mincore                         sys_mincore
91      common  madvise                         sys_madvise
92      common  shmget                          sys_shmget
93      common  shmat                           xtensa_shmat
94      common  shmctl                          sys_old_shmctl
95      common  shmdt                           sys_shmdt
96      common  socket                          sys_socket
97      common  setsockopt                      sys_setsockopt
98      common  getsockopt                      sys_getsockopt
99      common  shutdown                        sys_shutdown
100     common  bind                            sys_bind
101     common  connect                         sys_connect
102     common  listen                          sys_listen
103     common  accept                          sys_accept
104     common  getsockname                     sys_getsockname
105     common  getpeername                     sys_getpeername
106     common  sendmsg                         sys_sendmsg
107     common  recvmsg                         sys_recvmsg
108     common  send                            sys_send
109     common  recv                            sys_recv
110     common  sendto                          sys_sendto
111     common  recvfrom                        sys_recvfrom
112     common  socketpair                      sys_socketpair
113     common  sendfile                        sys_sendfile
114     common  sendfile64                      sys_sendfile64
115     common  sendmmsg                        sys_sendmmsg
116     common  clone                           sys_clone
117     common  execve                          sys_execve
118     common  exit                            sys_exit
119     common  exit_group                      sys_exit_group
120     common  getpid                          sys_getpid
121     common  wait4                           sys_wait4
122     common  waitid                          sys_waitid
123     common  kill                            sys_kill
124     common  tkill                           sys_tkill
125     common  tgkill                          sys_tgkill
126     common  set_tid_address                 sys_set_tid_address
127     common  gettid                          sys_gettid
128     common  setsid                          sys_setsid
129     common  getsid                          sys_getsid
130     common  prctl                           sys_prctl
131     common  personality                     sys_personality
132     common  getpriority                     sys_getpriority
133     common  setpriority                     sys_setpriority
134     common  setitimer                       sys_setitimer
135     common  getitimer                       sys_getitimer
136     common  setuid                          sys_setuid
137     common  getuid                          sys_getuid
138     common  setgid                          sys_setgid
139     common  getgid                          sys_getgid
140     common  geteuid                         sys_geteuid
141     common  getegid                         sys_getegid
142     common  setreuid                        sys_setreuid
143     common  setregid                        sys_setregid
144     common  setresuid                       sys_setresuid
145     common  getresuid                       sys_getresuid
146     common  setresgid                       sys_setresgid
147     common  getresgid                       sys_getresgid
148     common  setpgid                         sys_setpgid
149     common  getpgid                         sys_getpgid
150     common  getppid                         sys_getppid
151     common  getpgrp                         sys_getpgrp
152     common  reserved152                     sys_ni_syscall
153     common  reserved153                     sys_ni_syscall
154     common  times                           sys_times
155     common  acct                            sys_acct
156     common  sched_setaffinity               sys_sched_setaffinity
157     common  sched_getaffinity               sys_sched_getaffinity
158     common  capget                          sys_capget
159     common  capset                          sys_capset
160     common  ptrace                          sys_ptrace
161     common  semtimedop                      sys_semtimedop_time32
162     common  semget                          sys_semget
163     common  semop                           sys_semop
164     common  semctl                          sys_old_semctl
165     common  available165                    sys_ni_syscall
166     common  msgget                          sys_msgget
167     common  msgsnd                          sys_msgsnd
168     common  msgrcv                          sys_msgrcv
169     common  msgctl                          sys_old_msgctl
170     common  available170                    sys_ni_syscall
171     common  umount2                         sys_umount
172     common  mount                           sys_mount
173     common  swapon                          sys_swapon
174     common  chroot                          sys_chroot
175     common  pivot_root                      sys_pivot_root
176     common  umount                          sys_oldumount
177     common  swapoff                         sys_swapoff
178     common  sync                            sys_sync
179     common  syncfs                          sys_syncfs
180     common  setfsuid                        sys_setfsuid
181     common  setfsgid                        sys_setfsgid
182     common  sysfs                           sys_sysfs
183     common  ustat                           sys_ustat
184     common  statfs                          sys_statfs
185     common  fstatfs                         sys_fstatfs
186     common  statfs64                        sys_statfs64
187     common  fstatfs64                       sys_fstatfs64
188     common  setrlimit                       sys_setrlimit
189     common  getrlimit                       sys_getrlimit
190     common  getrusage                       sys_getrusage
191     common  futex                           sys_futex_time32
192     common  gettimeofday                    sys_gettimeofday
193     common  settimeofday                    sys_settimeofday
194     common  adjtimex                        sys_adjtimex_time32
195     common  nanosleep                       sys_nanosleep_time32
196     common  getgroups                       sys_getgroups
197     common  setgroups                       sys_setgroups
198     common  sethostname                     sys_sethostname
199     common  setdomainname                   sys_setdomainname
200     common  syslog                          sys_syslog
201     common  vhangup                         sys_vhangup
202     common  uselib                          sys_uselib
203     common  reboot                          sys_reboot
204     common  quotactl                        sys_quotactl
205     common  nfsservctl                      sys_ni_syscall
206     common  _sysctl                         sys_ni_syscall
207     common  bdflush                         sys_ni_syscall
208     common  uname                           sys_newuname
209     common  sysinfo                         sys_sysinfo
210     common  init_module                     sys_init_module
211     common  delete_module                   sys_delete_module
212     common  sched_setparam                  sys_sched_setparam
213     common  sched_getparam                  sys_sched_getparam
214     common  sched_setscheduler              sys_sched_setscheduler
215     common  sched_getscheduler              sys_sched_getscheduler
216     common  sched_get_priority_max          sys_sched_get_priority_max
217     common  sched_get_priority_min          sys_sched_get_priority_min
218     common  sched_rr_get_interval           sys_sched_rr_get_interval_time32
219     common  sched_yield                     sys_sched_yield
222     common  available222                    sys_ni_syscall
223     common  restart_syscall                 sys_restart_syscall
224     common  sigaltstack                     sys_sigaltstack
225     common  rt_sigreturn                    xtensa_rt_sigreturn
226     common  rt_sigaction                    sys_rt_sigaction
227     common  rt_sigprocmask                  sys_rt_sigprocmask
228     common  rt_sigpending                   sys_rt_sigpending
229     common  rt_sigtimedwait                 sys_rt_sigtimedwait_time32
230     common  rt_sigqueueinfo                 sys_rt_sigqueueinfo
231     common  rt_sigsuspend                   sys_rt_sigsuspend
232     common  mq_open                         sys_mq_open
233     common  mq_unlink                       sys_mq_unlink
234     common  mq_timedsend                    sys_mq_timedsend_time32
235     common  mq_timedreceive                 sys_mq_timedreceive_time32
236     common  mq_notify                       sys_mq_notify
237     common  mq_getsetattr                   sys_mq_getsetattr
238     common  available238                    sys_ni_syscall
239     common  io_setup                        sys_io_setup
240     common  io_destroy                      sys_io_destroy
241     common  io_submit                       sys_io_submit
242     common  io_getevents                    sys_io_getevents_time32
243     common  io_cancel                       sys_io_cancel
244     common  clock_settime                   sys_clock_settime32
245     common  clock_gettime                   sys_clock_gettime32
246     common  clock_getres                    sys_clock_getres_time32
247     common  clock_nanosleep                 sys_clock_nanosleep_time32
248     common  timer_create                    sys_timer_create
249     common  timer_delete                    sys_timer_delete
250     common  timer_settime                   sys_timer_settime32
251     common  timer_gettime                   sys_timer_gettime32
252     common  timer_getoverrun                sys_timer_getoverrun
253     common  reserved253                     sys_ni_syscall
254     common  lookup_dcookie                  sys_ni_syscall
255     common  available255                    sys_ni_syscall
256     common  add_key                         sys_add_key
257     common  request_key                     sys_request_key
258     common  keyctl                          sys_keyctl
259     common  available259                    sys_ni_syscall
260     common  readahead                       sys_readahead
261     common  remap_file_pages                sys_remap_file_pages
262     common  migrate_pages                   sys_migrate_pages
263     common  mbind                           sys_mbind
264     common  get_mempolicy                   sys_get_mempolicy
265     common  set_mempolicy                   sys_set_mempolicy
266     common  unshare                         sys_unshare
267     common  move_pages                      sys_move_pages
268     common  splice                          sys_splice
269     common  tee                             sys_tee
270     common  vmsplice                        sys_vmsplice
271     common  available271                    sys_ni_syscall
272     common  pselect6                        sys_pselect6_time32
273     common  ppoll                           sys_ppoll_time32
274     common  epoll_pwait                     sys_epoll_pwait
275     common  epoll_create1                   sys_epoll_create1
276     common  inotify_init                    sys_inotify_init
277     common  inotify_add_watch               sys_inotify_add_watch
278     common  inotify_rm_watch                sys_inotify_rm_watch
279     common  inotify_init1                   sys_inotify_init1
280     common  getcpu                          sys_getcpu
281     common  kexec_load                      sys_ni_syscall
282     common  ioprio_set                      sys_ioprio_set
283     common  ioprio_get                      sys_ioprio_get
284     common  set_robust_list                 sys_set_robust_list
285     common  get_robust_list                 sys_get_robust_list
286     common  available286                    sys_ni_syscall
287     common  available287                    sys_ni_syscall
288     common  openat                          sys_openat
289     common  mkdirat                         sys_mkdirat
290     common  mknodat                         sys_mknodat
291     common  unlinkat                        sys_unlinkat
292     common  renameat                        sys_renameat
293     common  linkat                          sys_linkat
294     common  symlinkat                       sys_symlinkat
295     common  readlinkat                      sys_readlinkat
296     common  utimensat                       sys_utimensat_time32
297     common  fchownat                        sys_fchownat
298     common  futimesat                       sys_futimesat_time32
299     common  fstatat64                       sys_fstatat64
300     common  fchmodat                        sys_fchmodat
301     common  faccessat                       sys_faccessat
302     common  available302                    sys_ni_syscall
303     common  available303                    sys_ni_syscall
304     common  signalfd                        sys_signalfd
306     common  eventfd                         sys_eventfd
307     common  recvmmsg                        sys_recvmmsg_time32
308     common  setns                           sys_setns
309     common  signalfd4                       sys_signalfd4
310     common  dup3                            sys_dup3
311     common  pipe2                           sys_pipe2
312     common  timerfd_create                  sys_timerfd_create
313     common  timerfd_settime                 sys_timerfd_settime32
314     common  timerfd_gettime                 sys_timerfd_gettime32
315     common  available315                    sys_ni_syscall
316     common  eventfd2                        sys_eventfd2
317     common  preadv                          sys_preadv
318     common  pwritev                         sys_pwritev
319     common  available319                    sys_ni_syscall
320     common  fanotify_init                   sys_fanotify_init
321     common  fanotify_mark                   sys_fanotify_mark
322     common  process_vm_readv                sys_process_vm_readv
323     common  process_vm_writev               sys_process_vm_writev
324     common  name_to_handle_at               sys_name_to_handle_at
325     common  open_by_handle_at               sys_open_by_handle_at
326     common  sync_file_range2                sys_sync_file_range2
327     common  perf_event_open                 sys_perf_event_open
328     common  rt_tgsigqueueinfo               sys_rt_tgsigqueueinfo
329     common  clock_adjtime                   sys_clock_adjtime32
330     common  prlimit64                       sys_prlimit64
331     common  kcmp                            sys_kcmp
332     common  finit_module                    sys_finit_module
333     common  accept4                         sys_accept4
334     common  sched_setattr                   sys_sched_setattr
335     common  sched_getattr                   sys_sched_getattr
336     common  renameat2                       sys_renameat2
337     common  seccomp                         sys_seccomp
338     common  getrandom                       sys_getrandom
339     common  memfd_create                    sys_memfd_create
340     common  bpf                             sys_bpf
341     common  execveat                        sys_execveat
342     common  userfaultfd                     sys_userfaultfd
343     common  membarrier                      sys_membarrier
344     common  mlock2                          sys_mlock2
345     common  copy_file_range                 sys_copy_file_range
346     common  preadv2                         sys_preadv2
347     common  pwritev2                        sys_pwritev2
348     common  pkey_mprotect                   sys_pkey_mprotect
349     common  pkey_alloc                      sys_pkey_alloc
350     common  pkey_free                       sys_pkey_free
351     common  statx                           sys_statx
352     common  rseq                            sys_rseq
403     common  clock_gettime64                 sys_clock_gettime
404     common  clock_settime64                 sys_clock_settime
405     common  clock_adjtime64                 sys_clock_adjtime
406     common  clock_getres_time64             sys_clock_getres
407     common  clock_nanosleep_time64          sys_clock_nanosleep
408     common  timer_gettime64                 sys_timer_gettime
409     common  timer_settime64                 sys_timer_settime
410     common  timerfd_gettime64               sys_timerfd_gettime
411     common  timerfd_settime64               sys_timerfd_settime
412     common  utimensat_time64                sys_utimensat
413     common  pselect6_time64                 sys_pselect6
414     common  ppoll_time64                    sys_ppoll
416     common  io_pgetevents_time64            sys_io_pgetevents
417     common  recvmmsg_time64                 sys_recvmmsg
418     common  mq_timedsend_time64             sys_mq_timedsend
419     common  mq_timedreceive_time64          sys_mq_timedreceive
420     common  semtimedop_time64               sys_semtimedop
421     common  rt_sigtimedwait_time64          sys_rt_sigtimedwait
422     common  futex_time64                    sys_futex
423     common  sched_rr_get_interval_time64    sys_sched_rr_get_interval
424     common  pidfd_send_signal               sys_pidfd_send_signal
425     common  io_uring_setup                  sys_io_uring_setup
426     common  io_uring_enter                  sys_io_uring_enter
427     common  io_uring_register               sys_io_uring_register
428     common  open_tree                       sys_open_tree
429     common  move_mount                      sys_move_mount
430     common  fsopen                          sys_fsopen
431     common  fsconfig                        sys_fsconfig
432     common  fsmount                         sys_fsmount
433     common  fspick                          sys_fspick
434     common  pidfd_open                      sys_pidfd_open
435     common  clone3                          sys_clone3
436     common  close_range                     sys_close_range
437     common  openat2                         sys_openat2
438     common  pidfd_getfd                     sys_pidfd_getfd
439     common  faccessat2                      sys_faccessat2
440     common  process_madvise                 sys_process_madvise
441     common  epoll_pwait2                    sys_epoll_pwait2
442     common  mount_setattr                   sys_mount_setattr
443     common  quotactl_fd                     sys_quotactl_fd
444     common  landlock_create_ruleset         sys_landlock_create_ruleset
445     common  landlock_add_rule               sys_landlock_add_rule
446     common  landlock_restrict_self          sys_landlock_restrict_self
448     common  process_mrelease                sys_process_mrelease
449     common  futex_waitv                     sys_futex_waitv
450     common  set_mempolicy_home_node         sys_set_mempolicy_home_node
451     common  cachestat                       sys_cachestat
452     common  fchmodat2                       sys_fchmodat2
453     common  map_shadow_stack                sys_map_shadow_stack
454     common  futex_wake                      sys_futex_wake
455     common  futex_wait                      sys_futex_wait
456     common  futex_requeue                   sys_futex_requeue
457     common  statmount                       sys_statmount
458     common  listmount                       sys_listmount
459     common  lsm_get_self_attr               sys_lsm_get_self_attr
460     common  lsm_set_self_attr               sys_lsm_set_self_attr
461     common  lsm_list_modules                sys_lsm_list_modules
462     common  mseal                           sys_mseal
463     common  setxattrat                      sys_setxattrat
464     common  getxattrat                      sys_getxattrat
465     common  listxattrat                     sys_listxattrat
466     common  removexattrat                   sys_removexattrat
467     common  open_tree_attr                  sys_open_tree_attr
468     common  file_getattr                    sys_file_getattr
469     common  file_setattr                    sys_file_setattr
470     common  listns                          sys_listns
471     common  rseq_slice_yield                sys_rseq_slice_yield
"""


# CRIS
# [How to make]
# cd /path/to/linux-4.16.18/
# awk '/sys_call_table:/,/^$/' arch/cris/arch-v10/kernel/entry.S \
# | grep -o "\.long \w*" | nl -v0 | awk '{print $1" cris "substr($3,5)" "$3}' |column -t
cris_syscall_tbl = """
0    cris  restart_syscall         sys_restart_syscall
1    cris  exit                    sys_exit
2    cris  fork                    sys_fork
3    cris  read                    sys_read
4    cris  write                   sys_write
5    cris  open                    sys_open
6    cris  close                   sys_close
7    cris  waitpid                 sys_waitpid
8    cris  creat                   sys_creat
9    cris  link                    sys_link
10   cris  unlink                  sys_unlink
11   cris  execve                  sys_execve
12   cris  chdir                   sys_chdir
13   cris  time                    sys_time
14   cris  mknod                   sys_mknod
15   cris  chmod                   sys_chmod
16   cris  lchown16                sys_lchown16
17   cris  ni_syscall              sys_ni_syscall
18   cris  stat                    sys_stat
19   cris  lseek                   sys_lseek
20   cris  getpid                  sys_getpid
21   cris  mount                   sys_mount
22   cris  oldumount               sys_oldumount
23   cris  setuid16                sys_setuid16
24   cris  getuid16                sys_getuid16
25   cris  stime                   sys_stime
26   cris  ptrace                  sys_ptrace
27   cris  alarm                   sys_alarm
28   cris  fstat                   sys_fstat
29   cris  pause                   sys_pause
30   cris  utime                   sys_utime
31   cris  ni_syscall              sys_ni_syscall
32   cris  ni_syscall              sys_ni_syscall
33   cris  access                  sys_access
34   cris  nice                    sys_nice
35   cris  ni_syscall              sys_ni_syscall
36   cris  sync                    sys_sync
37   cris  kill                    sys_kill
38   cris  rename                  sys_rename
39   cris  mkdir                   sys_mkdir
40   cris  rmdir                   sys_rmdir
41   cris  dup                     sys_dup
42   cris  pipe                    sys_pipe
43   cris  times                   sys_times
44   cris  ni_syscall              sys_ni_syscall
45   cris  brk                     sys_brk
46   cris  setgid16                sys_setgid16
47   cris  getgid16                sys_getgid16
48   cris  signal                  sys_signal
49   cris  geteuid16               sys_geteuid16
50   cris  getegid16               sys_getegid16
51   cris  acct                    sys_acct
52   cris  umount                  sys_umount
53   cris  ni_syscall              sys_ni_syscall
54   cris  ioctl                   sys_ioctl
55   cris  fcntl                   sys_fcntl
56   cris  ni_syscall              sys_ni_syscall
57   cris  setpgid                 sys_setpgid
58   cris  ni_syscall              sys_ni_syscall
59   cris  ni_syscall              sys_ni_syscall
60   cris  umask                   sys_umask
61   cris  chroot                  sys_chroot
62   cris  ustat                   sys_ustat
63   cris  dup2                    sys_dup2
64   cris  getppid                 sys_getppid
65   cris  getpgrp                 sys_getpgrp
66   cris  setsid                  sys_setsid
67   cris  sigaction               sys_sigaction
68   cris  sgetmask                sys_sgetmask
69   cris  ssetmask                sys_ssetmask
70   cris  setreuid16              sys_setreuid16
71   cris  setregid16              sys_setregid16
72   cris  sigsuspend              sys_sigsuspend
73   cris  sigpending              sys_sigpending
74   cris  sethostname             sys_sethostname
75   cris  setrlimit               sys_setrlimit
76   cris  old_getrlimit           sys_old_getrlimit
77   cris  getrusage               sys_getrusage
78   cris  gettimeofday            sys_gettimeofday
79   cris  settimeofday            sys_settimeofday
80   cris  getgroups16             sys_getgroups16
81   cris  setgroups16             sys_setgroups16
82   cris  select                  sys_select
83   cris  symlink                 sys_symlink
84   cris  lstat                   sys_lstat
85   cris  readlink                sys_readlink
86   cris  uselib                  sys_uselib
87   cris  swapon                  sys_swapon
88   cris  reboot                  sys_reboot
89   cris  old_readdir             sys_old_readdir
90   cris  old_mmap                sys_old_mmap
91   cris  munmap                  sys_munmap
92   cris  truncate                sys_truncate
93   cris  ftruncate               sys_ftruncate
94   cris  fchmod                  sys_fchmod
95   cris  fchown16                sys_fchown16
96   cris  getpriority             sys_getpriority
97   cris  setpriority             sys_setpriority
98   cris  ni_syscall              sys_ni_syscall
99   cris  statfs                  sys_statfs
100  cris  fstatfs                 sys_fstatfs
101  cris  ni_syscall              sys_ni_syscall
102  cris  socketcall              sys_socketcall
103  cris  syslog                  sys_syslog
104  cris  setitimer               sys_setitimer
105  cris  getitimer               sys_getitimer
106  cris  newstat                 sys_newstat
107  cris  newlstat                sys_newlstat
108  cris  newfstat                sys_newfstat
109  cris  ni_syscall              sys_ni_syscall
110  cris  ni_syscall              sys_ni_syscall
111  cris  vhangup                 sys_vhangup
112  cris  ni_syscall              sys_ni_syscall
113  cris  ni_syscall              sys_ni_syscall
114  cris  wait4                   sys_wait4
115  cris  swapoff                 sys_swapoff
116  cris  sysinfo                 sys_sysinfo
117  cris  ipc                     sys_ipc
118  cris  fsync                   sys_fsync
119  cris  sigreturn               sys_sigreturn
120  cris  clone                   sys_clone
121  cris  setdomainname           sys_setdomainname
122  cris  newuname                sys_newuname
123  cris  ni_syscall              sys_ni_syscall
124  cris  adjtimex                sys_adjtimex
125  cris  mprotect                sys_mprotect
126  cris  sigprocmask             sys_sigprocmask
127  cris  ni_syscall              sys_ni_syscall
128  cris  init_module             sys_init_module
129  cris  delete_module           sys_delete_module
130  cris  ni_syscall              sys_ni_syscall
131  cris  quotactl                sys_quotactl
132  cris  getpgid                 sys_getpgid
133  cris  fchdir                  sys_fchdir
134  cris  bdflush                 sys_bdflush
135  cris  sysfs                   sys_sysfs
136  cris  personality             sys_personality
137  cris  ni_syscall              sys_ni_syscall
138  cris  setfsuid16              sys_setfsuid16
139  cris  setfsgid16              sys_setfsgid16
140  cris  llseek                  sys_llseek
141  cris  getdents                sys_getdents
142  cris  select                  sys_select
143  cris  flock                   sys_flock
144  cris  msync                   sys_msync
145  cris  readv                   sys_readv
146  cris  writev                  sys_writev
147  cris  getsid                  sys_getsid
148  cris  fdatasync               sys_fdatasync
149  cris  sysctl                  sys_sysctl
150  cris  mlock                   sys_mlock
151  cris  munlock                 sys_munlock
152  cris  mlockall                sys_mlockall
153  cris  munlockall              sys_munlockall
154  cris  sched_setparam          sys_sched_setparam
155  cris  sched_getparam          sys_sched_getparam
156  cris  sched_setscheduler      sys_sched_setscheduler
157  cris  sched_getscheduler      sys_sched_getscheduler
158  cris  sched_yield             sys_sched_yield
159  cris  sched_get_priority_max  sys_sched_get_priority_max
160  cris  sched_get_priority_min  sys_sched_get_priority_min
161  cris  sched_rr_get_interval   sys_sched_rr_get_interval
162  cris  nanosleep               sys_nanosleep
163  cris  mremap                  sys_mremap
164  cris  setresuid16             sys_setresuid16
165  cris  getresuid16             sys_getresuid16
166  cris  ni_syscall              sys_ni_syscall
167  cris  ni_syscall              sys_ni_syscall
168  cris  poll                    sys_poll
169  cris  ni_syscall              sys_ni_syscall
170  cris  setresgid16             sys_setresgid16
171  cris  getresgid16             sys_getresgid16
172  cris  prctl                   sys_prctl
173  cris  rt_sigreturn            sys_rt_sigreturn
174  cris  rt_sigaction            sys_rt_sigaction
175  cris  rt_sigprocmask          sys_rt_sigprocmask
176  cris  rt_sigpending           sys_rt_sigpending
177  cris  rt_sigtimedwait         sys_rt_sigtimedwait
178  cris  rt_sigqueueinfo         sys_rt_sigqueueinfo
179  cris  rt_sigsuspend           sys_rt_sigsuspend
180  cris  pread64                 sys_pread64
181  cris  pwrite64                sys_pwrite64
182  cris  chown16                 sys_chown16
183  cris  getcwd                  sys_getcwd
184  cris  capget                  sys_capget
185  cris  capset                  sys_capset
186  cris  sigaltstack             sys_sigaltstack
187  cris  sendfile                sys_sendfile
188  cris  ni_syscall              sys_ni_syscall
189  cris  ni_syscall              sys_ni_syscall
190  cris  vfork                   sys_vfork
191  cris  getrlimit               sys_getrlimit
192  cris  mmap2                   sys_mmap2
193  cris  truncate64              sys_truncate64
194  cris  ftruncate64             sys_ftruncate64
195  cris  stat64                  sys_stat64
196  cris  lstat64                 sys_lstat64
197  cris  fstat64                 sys_fstat64
198  cris  lchown                  sys_lchown
199  cris  getuid                  sys_getuid
200  cris  getgid                  sys_getgid
201  cris  geteuid                 sys_geteuid
202  cris  getegid                 sys_getegid
203  cris  setreuid                sys_setreuid
204  cris  setregid                sys_setregid
205  cris  getgroups               sys_getgroups
206  cris  setgroups               sys_setgroups
207  cris  fchown                  sys_fchown
208  cris  setresuid               sys_setresuid
209  cris  getresuid               sys_getresuid
210  cris  setresgid               sys_setresgid
211  cris  getresgid               sys_getresgid
212  cris  chown                   sys_chown
213  cris  setuid                  sys_setuid
214  cris  setgid                  sys_setgid
215  cris  setfsuid                sys_setfsuid
216  cris  setfsgid                sys_setfsgid
217  cris  pivot_root              sys_pivot_root
218  cris  mincore                 sys_mincore
219  cris  madvise                 sys_madvise
220  cris  getdents64              sys_getdents64
221  cris  fcntl64                 sys_fcntl64
222  cris  ni_syscall              sys_ni_syscall
223  cris  ni_syscall              sys_ni_syscall
224  cris  gettid                  sys_gettid
225  cris  readahead               sys_readahead
226  cris  setxattr                sys_setxattr
227  cris  lsetxattr               sys_lsetxattr
228  cris  fsetxattr               sys_fsetxattr
229  cris  getxattr                sys_getxattr
230  cris  lgetxattr               sys_lgetxattr
231  cris  fgetxattr               sys_fgetxattr
232  cris  listxattr               sys_listxattr
233  cris  llistxattr              sys_llistxattr
234  cris  flistxattr              sys_flistxattr
235  cris  removexattr             sys_removexattr
236  cris  lremovexattr            sys_lremovexattr
237  cris  fremovexattr            sys_fremovexattr
238  cris  tkill                   sys_tkill
239  cris  sendfile64              sys_sendfile64
240  cris  futex                   sys_futex
241  cris  sched_setaffinity       sys_sched_setaffinity
242  cris  sched_getaffinity       sys_sched_getaffinity
243  cris  ni_syscall              sys_ni_syscall
244  cris  ni_syscall              sys_ni_syscall
245  cris  io_setup                sys_io_setup
246  cris  io_destroy              sys_io_destroy
247  cris  io_getevents            sys_io_getevents
248  cris  io_submit               sys_io_submit
249  cris  io_cancel               sys_io_cancel
250  cris  fadvise64               sys_fadvise64
251  cris  ni_syscall              sys_ni_syscall
252  cris  exit_group              sys_exit_group
253  cris  lookup_dcookie          sys_lookup_dcookie
254  cris  epoll_create            sys_epoll_create
255  cris  epoll_ctl               sys_epoll_ctl
256  cris  epoll_wait              sys_epoll_wait
257  cris  remap_file_pages        sys_remap_file_pages
258  cris  set_tid_address         sys_set_tid_address
259  cris  timer_create            sys_timer_create
260  cris  timer_settime           sys_timer_settime
261  cris  timer_gettime           sys_timer_gettime
262  cris  timer_getoverrun        sys_timer_getoverrun
263  cris  timer_delete            sys_timer_delete
264  cris  clock_settime           sys_clock_settime
265  cris  clock_gettime           sys_clock_gettime
266  cris  clock_getres            sys_clock_getres
267  cris  clock_nanosleep         sys_clock_nanosleep
268  cris  statfs64                sys_statfs64
269  cris  fstatfs64               sys_fstatfs64
270  cris  tgkill                  sys_tgkill
271  cris  utimes                  sys_utimes
272  cris  fadvise64_64            sys_fadvise64_64
273  cris  ni_syscall              sys_ni_syscall
274  cris  ni_syscall              sys_ni_syscall
275  cris  ni_syscall              sys_ni_syscall
276  cris  ni_syscall              sys_ni_syscall
277  cris  mq_open                 sys_mq_open
278  cris  mq_unlink               sys_mq_unlink
279  cris  mq_timedsend            sys_mq_timedsend
280  cris  mq_timedreceive         sys_mq_timedreceive
281  cris  mq_notify               sys_mq_notify
282  cris  mq_getsetattr           sys_mq_getsetattr
283  cris  ni_syscall              sys_ni_syscall
284  cris  waitid                  sys_waitid
285  cris  ni_syscall              sys_ni_syscall
286  cris  add_key                 sys_add_key
287  cris  request_key             sys_request_key
288  cris  keyctl                  sys_keyctl
289  cris  ioprio_set              sys_ioprio_set
290  cris  ioprio_get              sys_ioprio_get
291  cris  inotify_init            sys_inotify_init
292  cris  inotify_add_watch       sys_inotify_add_watch
293  cris  inotify_rm_watch        sys_inotify_rm_watch
294  cris  migrate_pages           sys_migrate_pages
295  cris  openat                  sys_openat
296  cris  mkdirat                 sys_mkdirat
297  cris  mknodat                 sys_mknodat
298  cris  fchownat                sys_fchownat
299  cris  futimesat               sys_futimesat
300  cris  fstatat64               sys_fstatat64
301  cris  unlinkat                sys_unlinkat
302  cris  renameat                sys_renameat
303  cris  linkat                  sys_linkat
304  cris  symlinkat               sys_symlinkat
305  cris  readlinkat              sys_readlinkat
306  cris  fchmodat                sys_fchmodat
307  cris  faccessat               sys_faccessat
308  cris  pselect6                sys_pselect6
309  cris  ppoll                   sys_ppoll
310  cris  unshare                 sys_unshare
311  cris  set_robust_list         sys_set_robust_list
312  cris  get_robust_list         sys_get_robust_list
313  cris  splice                  sys_splice
314  cris  sync_file_range         sys_sync_file_range
315  cris  tee                     sys_tee
316  cris  vmsplice                sys_vmsplice
317  cris  move_pages              sys_move_pages
318  cris  getcpu                  sys_getcpu
319  cris  epoll_pwait             sys_epoll_pwait
320  cris  utimensat               sys_utimensat
321  cris  signalfd                sys_signalfd
322  cris  timerfd_create          sys_timerfd_create
323  cris  eventfd                 sys_eventfd
324  cris  fallocate               sys_fallocate
325  cris  timerfd_settime         sys_timerfd_settime
326  cris  timerfd_gettime         sys_timerfd_gettime
327  cris  signalfd4               sys_signalfd4
328  cris  eventfd2                sys_eventfd2
329  cris  epoll_create1           sys_epoll_create1
330  cris  dup3                    sys_dup3
331  cris  pipe2                   sys_pipe2
332  cris  inotify_init1           sys_inotify_init1
333  cris  preadv                  sys_preadv
334  cris  pwritev                 sys_pwritev
335  cris  setns                   sys_setns
336  cris  name_to_handle_at       sys_name_to_handle_at
337  cris  open_by_handle_at       sys_open_by_handle_at
338  cris  rt_tgsigqueueinfo       sys_rt_tgsigqueueinfo
339  cris  perf_event_open         sys_perf_event_open
340  cris  recvmmsg                sys_recvmmsg
341  cris  accept4                 sys_accept4
342  cris  fanotify_init           sys_fanotify_init
343  cris  fanotify_mark           sys_fanotify_mark
344  cris  prlimit64               sys_prlimit64
345  cris  clock_adjtime           sys_clock_adjtime
346  cris  syncfs                  sys_syncfs
347  cris  sendmmsg                sys_sendmmsg
348  cris  process_vm_readv        sys_process_vm_readv
349  cris  process_vm_writev       sys_process_vm_writev
350  cris  kcmp                    sys_kcmp
351  cris  finit_module            sys_finit_module
352  cris  sched_setattr           sys_sched_setattr
353  cris  sched_getattr           sys_sched_getattr
354  cris  renameat2               sys_renameat2
355  cris  seccomp                 sys_seccomp
356  cris  getrandom               sys_getrandom
357  cris  memfd_create            sys_memfd_create
358  cris  bpf                     sys_bpf
359  cris  execveat                sys_execveat
"""


# Loongarch
#
# [How to make for 6.10.14]
# cd /path/to/linux-6.10.14/
# gcc -I `pwd`/include/uapi/ -E -D__SYSCALL=SYSCALL arch/loongarch/include/uapi/asm/unistd.h | grep ^SYSCALL \
# | sed -e 's/SYSCALL(//;s/[,)]//g' > /tmp/a
# grep -oP "__NR\S+\s+\d+$" include/uapi/asm-generic/unistd.h | grep -v __NR_sync_file_range2 > /tmp/b
# join -2 2 -o 1.1,1.10,2.1,1.2 -e loongarch /tmp/a /tmp/b | sed -e 's/\(__NR_\|__NR3264_\)//g' | column -t
loongarch_syscall_tbl = """
0    loongarch  io_setup                 sys_io_setup
1    loongarch  io_destroy               sys_io_destroy
2    loongarch  io_submit                sys_io_submit
3    loongarch  io_cancel                sys_io_cancel
4    loongarch  io_getevents             sys_io_getevents
5    loongarch  setxattr                 sys_setxattr
6    loongarch  lsetxattr                sys_lsetxattr
7    loongarch  fsetxattr                sys_fsetxattr
8    loongarch  getxattr                 sys_getxattr
9    loongarch  lgetxattr                sys_lgetxattr
10   loongarch  fgetxattr                sys_fgetxattr
11   loongarch  listxattr                sys_listxattr
12   loongarch  llistxattr               sys_llistxattr
13   loongarch  flistxattr               sys_flistxattr
14   loongarch  removexattr              sys_removexattr
15   loongarch  lremovexattr             sys_lremovexattr
16   loongarch  fremovexattr             sys_fremovexattr
17   loongarch  getcwd                   sys_getcwd
18   loongarch  lookup_dcookie           sys_ni_syscall
19   loongarch  eventfd2                 sys_eventfd2
20   loongarch  epoll_create1            sys_epoll_create1
21   loongarch  epoll_ctl                sys_epoll_ctl
22   loongarch  epoll_pwait              sys_epoll_pwait
23   loongarch  dup                      sys_dup
24   loongarch  dup3                     sys_dup3
25   loongarch  fcntl                    sys_fcntl
26   loongarch  inotify_init1            sys_inotify_init1
27   loongarch  inotify_add_watch        sys_inotify_add_watch
28   loongarch  inotify_rm_watch         sys_inotify_rm_watch
29   loongarch  ioctl                    sys_ioctl
30   loongarch  ioprio_set               sys_ioprio_set
31   loongarch  ioprio_get               sys_ioprio_get
32   loongarch  flock                    sys_flock
33   loongarch  mknodat                  sys_mknodat
34   loongarch  mkdirat                  sys_mkdirat
35   loongarch  unlinkat                 sys_unlinkat
36   loongarch  symlinkat                sys_symlinkat
37   loongarch  linkat                   sys_linkat
39   loongarch  umount2                  sys_umount
40   loongarch  mount                    sys_mount
41   loongarch  pivot_root               sys_pivot_root
42   loongarch  nfsservctl               sys_ni_syscall
43   loongarch  statfs                   sys_statfs
44   loongarch  fstatfs                  sys_fstatfs
45   loongarch  truncate                 sys_truncate
46   loongarch  ftruncate                sys_ftruncate
47   loongarch  fallocate                sys_fallocate
48   loongarch  faccessat                sys_faccessat
49   loongarch  chdir                    sys_chdir
50   loongarch  fchdir                   sys_fchdir
51   loongarch  chroot                   sys_chroot
52   loongarch  fchmod                   sys_fchmod
53   loongarch  fchmodat                 sys_fchmodat
54   loongarch  fchownat                 sys_fchownat
55   loongarch  fchown                   sys_fchown
56   loongarch  openat                   sys_openat
57   loongarch  close                    sys_close
58   loongarch  vhangup                  sys_vhangup
59   loongarch  pipe2                    sys_pipe2
60   loongarch  quotactl                 sys_quotactl
61   loongarch  getdents64               sys_getdents64
62   loongarch  lseek                    sys_lseek
63   loongarch  read                     sys_read
64   loongarch  write                    sys_write
65   loongarch  readv                    sys_readv
66   loongarch  writev                   sys_writev
67   loongarch  pread64                  sys_pread64
68   loongarch  pwrite64                 sys_pwrite64
69   loongarch  preadv                   sys_preadv
70   loongarch  pwritev                  sys_pwritev
71   loongarch  sendfile                 sys_sendfile64
72   loongarch  pselect6                 sys_pselect6
73   loongarch  ppoll                    sys_ppoll
74   loongarch  signalfd4                sys_signalfd4
75   loongarch  vmsplice                 sys_vmsplice
76   loongarch  splice                   sys_splice
77   loongarch  tee                      sys_tee
78   loongarch  readlinkat               sys_readlinkat
81   loongarch  sync                     sys_sync
82   loongarch  fsync                    sys_fsync
83   loongarch  fdatasync                sys_fdatasync
84   loongarch  sync_file_range          sys_sync_file_range
85   loongarch  timerfd_create           sys_timerfd_create
86   loongarch  timerfd_settime          sys_timerfd_settime
87   loongarch  timerfd_gettime          sys_timerfd_gettime
88   loongarch  utimensat                sys_utimensat
89   loongarch  acct                     sys_acct
90   loongarch  capget                   sys_capget
91   loongarch  capset                   sys_capset
92   loongarch  personality              sys_personality
93   loongarch  exit                     sys_exit
94   loongarch  exit_group               sys_exit_group
95   loongarch  waitid                   sys_waitid
96   loongarch  set_tid_address          sys_set_tid_address
97   loongarch  unshare                  sys_unshare
98   loongarch  futex                    sys_futex
99   loongarch  set_robust_list          sys_set_robust_list
100  loongarch  get_robust_list          sys_get_robust_list
101  loongarch  nanosleep                sys_nanosleep
102  loongarch  getitimer                sys_getitimer
103  loongarch  setitimer                sys_setitimer
104  loongarch  kexec_load               sys_kexec_load
105  loongarch  init_module              sys_init_module
106  loongarch  delete_module            sys_delete_module
107  loongarch  timer_create             sys_timer_create
108  loongarch  timer_gettime            sys_timer_gettime
109  loongarch  timer_getoverrun         sys_timer_getoverrun
110  loongarch  timer_settime            sys_timer_settime
111  loongarch  timer_delete             sys_timer_delete
112  loongarch  clock_settime            sys_clock_settime
113  loongarch  clock_gettime            sys_clock_gettime
114  loongarch  clock_getres             sys_clock_getres
115  loongarch  clock_nanosleep          sys_clock_nanosleep
116  loongarch  syslog                   sys_syslog
117  loongarch  ptrace                   sys_ptrace
118  loongarch  sched_setparam           sys_sched_setparam
119  loongarch  sched_setscheduler       sys_sched_setscheduler
120  loongarch  sched_getscheduler       sys_sched_getscheduler
121  loongarch  sched_getparam           sys_sched_getparam
122  loongarch  sched_setaffinity        sys_sched_setaffinity
123  loongarch  sched_getaffinity        sys_sched_getaffinity
124  loongarch  sched_yield              sys_sched_yield
125  loongarch  sched_get_priority_max   sys_sched_get_priority_max
126  loongarch  sched_get_priority_min   sys_sched_get_priority_min
127  loongarch  sched_rr_get_interval    sys_sched_rr_get_interval
128  loongarch  restart_syscall          sys_restart_syscall
129  loongarch  kill                     sys_kill
130  loongarch  tkill                    sys_tkill
131  loongarch  tgkill                   sys_tgkill
132  loongarch  sigaltstack              sys_sigaltstack
133  loongarch  rt_sigsuspend            sys_rt_sigsuspend
134  loongarch  rt_sigaction             sys_rt_sigaction
135  loongarch  rt_sigprocmask           sys_rt_sigprocmask
136  loongarch  rt_sigpending            sys_rt_sigpending
137  loongarch  rt_sigtimedwait          sys_rt_sigtimedwait
138  loongarch  rt_sigqueueinfo          sys_rt_sigqueueinfo
139  loongarch  rt_sigreturn             sys_rt_sigreturn
140  loongarch  setpriority              sys_setpriority
141  loongarch  getpriority              sys_getpriority
142  loongarch  reboot                   sys_reboot
143  loongarch  setregid                 sys_setregid
144  loongarch  setgid                   sys_setgid
145  loongarch  setreuid                 sys_setreuid
146  loongarch  setuid                   sys_setuid
147  loongarch  setresuid                sys_setresuid
148  loongarch  getresuid                sys_getresuid
149  loongarch  setresgid                sys_setresgid
150  loongarch  getresgid                sys_getresgid
151  loongarch  setfsuid                 sys_setfsuid
152  loongarch  setfsgid                 sys_setfsgid
153  loongarch  times                    sys_times
154  loongarch  setpgid                  sys_setpgid
155  loongarch  getpgid                  sys_getpgid
156  loongarch  getsid                   sys_getsid
157  loongarch  setsid                   sys_setsid
158  loongarch  getgroups                sys_getgroups
159  loongarch  setgroups                sys_setgroups
160  loongarch  uname                    sys_newuname
161  loongarch  sethostname              sys_sethostname
162  loongarch  setdomainname            sys_setdomainname
165  loongarch  getrusage                sys_getrusage
166  loongarch  umask                    sys_umask
167  loongarch  prctl                    sys_prctl
168  loongarch  getcpu                   sys_getcpu
169  loongarch  gettimeofday             sys_gettimeofday
170  loongarch  settimeofday             sys_settimeofday
171  loongarch  adjtimex                 sys_adjtimex
172  loongarch  getpid                   sys_getpid
173  loongarch  getppid                  sys_getppid
174  loongarch  getuid                   sys_getuid
175  loongarch  geteuid                  sys_geteuid
176  loongarch  getgid                   sys_getgid
177  loongarch  getegid                  sys_getegid
178  loongarch  gettid                   sys_gettid
179  loongarch  sysinfo                  sys_sysinfo
180  loongarch  mq_open                  sys_mq_open
181  loongarch  mq_unlink                sys_mq_unlink
182  loongarch  mq_timedsend             sys_mq_timedsend
183  loongarch  mq_timedreceive          sys_mq_timedreceive
184  loongarch  mq_notify                sys_mq_notify
185  loongarch  mq_getsetattr            sys_mq_getsetattr
186  loongarch  msgget                   sys_msgget
187  loongarch  msgctl                   sys_msgctl
188  loongarch  msgrcv                   sys_msgrcv
189  loongarch  msgsnd                   sys_msgsnd
190  loongarch  semget                   sys_semget
191  loongarch  semctl                   sys_semctl
192  loongarch  semtimedop               sys_semtimedop
193  loongarch  semop                    sys_semop
194  loongarch  shmget                   sys_shmget
195  loongarch  shmctl                   sys_shmctl
196  loongarch  shmat                    sys_shmat
197  loongarch  shmdt                    sys_shmdt
198  loongarch  socket                   sys_socket
199  loongarch  socketpair               sys_socketpair
200  loongarch  bind                     sys_bind
201  loongarch  listen                   sys_listen
202  loongarch  accept                   sys_accept
203  loongarch  connect                  sys_connect
204  loongarch  getsockname              sys_getsockname
205  loongarch  getpeername              sys_getpeername
206  loongarch  sendto                   sys_sendto
207  loongarch  recvfrom                 sys_recvfrom
208  loongarch  setsockopt               sys_setsockopt
209  loongarch  getsockopt               sys_getsockopt
210  loongarch  shutdown                 sys_shutdown
211  loongarch  sendmsg                  sys_sendmsg
212  loongarch  recvmsg                  sys_recvmsg
213  loongarch  readahead                sys_readahead
214  loongarch  brk                      sys_brk
215  loongarch  munmap                   sys_munmap
216  loongarch  mremap                   sys_mremap
217  loongarch  add_key                  sys_add_key
218  loongarch  request_key              sys_request_key
219  loongarch  keyctl                   sys_keyctl
220  loongarch  clone                    sys_clone
221  loongarch  execve                   sys_execve
222  loongarch  mmap                     sys_mmap
223  loongarch  fadvise64                sys_fadvise64_64
224  loongarch  swapon                   sys_swapon
225  loongarch  swapoff                  sys_swapoff
226  loongarch  mprotect                 sys_mprotect
227  loongarch  msync                    sys_msync
228  loongarch  mlock                    sys_mlock
229  loongarch  munlock                  sys_munlock
230  loongarch  mlockall                 sys_mlockall
231  loongarch  munlockall               sys_munlockall
232  loongarch  mincore                  sys_mincore
233  loongarch  madvise                  sys_madvise
234  loongarch  remap_file_pages         sys_remap_file_pages
235  loongarch  mbind                    sys_mbind
236  loongarch  get_mempolicy            sys_get_mempolicy
237  loongarch  set_mempolicy            sys_set_mempolicy
238  loongarch  migrate_pages            sys_migrate_pages
239  loongarch  move_pages               sys_move_pages
240  loongarch  rt_tgsigqueueinfo        sys_rt_tgsigqueueinfo
241  loongarch  perf_event_open          sys_perf_event_open
242  loongarch  accept4                  sys_accept4
243  loongarch  recvmmsg                 sys_recvmmsg
260  loongarch  wait4                    sys_wait4
261  loongarch  prlimit64                sys_prlimit64
262  loongarch  fanotify_init            sys_fanotify_init
263  loongarch  fanotify_mark            sys_fanotify_mark
264  loongarch  name_to_handle_at        sys_name_to_handle_at
265  loongarch  open_by_handle_at        sys_open_by_handle_at
266  loongarch  clock_adjtime            sys_clock_adjtime
267  loongarch  syncfs                   sys_syncfs
268  loongarch  setns                    sys_setns
269  loongarch  sendmmsg                 sys_sendmmsg
270  loongarch  process_vm_readv         sys_process_vm_readv
271  loongarch  process_vm_writev        sys_process_vm_writev
272  loongarch  kcmp                     sys_kcmp
273  loongarch  finit_module             sys_finit_module
274  loongarch  sched_setattr            sys_sched_setattr
275  loongarch  sched_getattr            sys_sched_getattr
276  loongarch  renameat2                sys_renameat2
277  loongarch  seccomp                  sys_seccomp
278  loongarch  getrandom                sys_getrandom
279  loongarch  memfd_create             sys_memfd_create
280  loongarch  bpf                      sys_bpf
281  loongarch  execveat                 sys_execveat
282  loongarch  userfaultfd              sys_userfaultfd
283  loongarch  membarrier               sys_membarrier
284  loongarch  mlock2                   sys_mlock2
285  loongarch  copy_file_range          sys_copy_file_range
286  loongarch  preadv2                  sys_preadv2
287  loongarch  pwritev2                 sys_pwritev2
288  loongarch  pkey_mprotect            sys_pkey_mprotect
289  loongarch  pkey_alloc               sys_pkey_alloc
290  loongarch  pkey_free                sys_pkey_free
291  loongarch  statx                    sys_statx
292  loongarch  io_pgetevents            sys_io_pgetevents
293  loongarch  rseq                     sys_rseq
294  loongarch  kexec_file_load          sys_kexec_file_load
424  loongarch  pidfd_send_signal        sys_pidfd_send_signal
425  loongarch  io_uring_setup           sys_io_uring_setup
426  loongarch  io_uring_enter           sys_io_uring_enter
427  loongarch  io_uring_register        sys_io_uring_register
428  loongarch  open_tree                sys_open_tree
429  loongarch  move_mount               sys_move_mount
430  loongarch  fsopen                   sys_fsopen
431  loongarch  fsconfig                 sys_fsconfig
432  loongarch  fsmount                  sys_fsmount
433  loongarch  fspick                   sys_fspick
434  loongarch  pidfd_open               sys_pidfd_open
435  loongarch  clone3                   sys_clone3
436  loongarch  close_range              sys_close_range
437  loongarch  openat2                  sys_openat2
438  loongarch  pidfd_getfd              sys_pidfd_getfd
439  loongarch  faccessat2               sys_faccessat2
440  loongarch  process_madvise          sys_process_madvise
441  loongarch  epoll_pwait2             sys_epoll_pwait2
442  loongarch  mount_setattr            sys_mount_setattr
443  loongarch  quotactl_fd              sys_quotactl_fd
444  loongarch  landlock_create_ruleset  sys_landlock_create_ruleset
445  loongarch  landlock_add_rule        sys_landlock_add_rule
446  loongarch  landlock_restrict_self   sys_landlock_restrict_self
448  loongarch  process_mrelease         sys_process_mrelease
449  loongarch  futex_waitv              sys_futex_waitv
450  loongarch  set_mempolicy_home_node  sys_set_mempolicy_home_node
451  loongarch  cachestat                sys_cachestat
452  loongarch  fchmodat2                sys_fchmodat2
453  loongarch  map_shadow_stack         sys_map_shadow_stack
454  loongarch  futex_wake               sys_futex_wake
455  loongarch  futex_wait               sys_futex_wait
456  loongarch  futex_requeue            sys_futex_requeue
457  loongarch  statmount                sys_statmount
458  loongarch  listmount                sys_listmount
459  loongarch  lsm_get_self_attr        sys_lsm_get_self_attr
460  loongarch  lsm_set_self_attr        sys_lsm_set_self_attr
461  loongarch  lsm_list_modules         sys_lsm_list_modules
462  loongarch  mseal                    sys_mseal
463  loongarch  setxattrat               sys_setxattrat
464  loongarch  getxattrat               sys_getxattrat
465  loongarch  listxattrat              sys_listxattrat
466  loongarch  removexattrat            sys_removexattrat
467  loongarch  open_tree_attr           sys_open_tree_attr
"""


# arc
arc_syscall_tbl = arm64_syscall_tbl


# csky
csky_syscall_tbl = arm64_syscall_tbl


# ARM/ARM64 OP-TEE (at secure world)
# - core/include/tee/tee_svc.h
# - core/include/tee/tee_svc_cryp.h
# - core/include/tee/tee_svc_storage.h
# - core/include/tee/svc_cache.h
arm_OPTEE_syscall_list = [
    [0x00, "syscall_sys_return", ["unsigned long ret"]],
    [0x01, "syscall_log", ["const void *buf", "size_t len"]],
    [0x02, "syscall_panic", ["unsigned long code"]],
    [0x03, "syscall_get_property", ["unsigned long prop_set", "unsigned long index", "void *name", "uint32_t *name_len", "void *buf", "uint32_t *blen", "uint32_t *prop_type"]],
    [0x04, "syscall_get_property_name_to_index", ["unsigned long prop_set", "void *name", "unsigned long name_len", "uint32_t *index"]],
    [0x05, "syscall_open_ta_session", ["const TEE_UUID *dest", "unsigned long cancel_req_to", "struct utee_params *params", "uint32_t *sess", "uint32_t *ret_orig"]],
    [0x06, "syscall_close_ta_session", ["unsigned long sess"]],
    [0x07, "syscall_invoke_ta_command", ["unsigned long sess", "unsigned long cancel_req_to", "unsigned long cmd_id", "struct utee_params *params", "uint32_t *ret_orig"]],
    [0x08, "syscall_check_access_rights", ["unsigned long flags", "const void *buf", "size_t len"]],
    [0x09, "syscall_get_cancellation_flag", ["uint32_t *cancel"]],
    [0x0a, "syscall_unmask_cancellation", ["uint32_t *old_mask"]],
    [0x0b, "syscall_mask_cancellation", ["uint32_t *old_mask"]],
    [0x0c, "syscall_wait", ["unsigned long timeout"]],
    [0x0d, "syscall_get_time", ["unsigned long cat", "TEE_Time *time"]],
    [0x0e, "syscall_set_ta_time", ["const TEE_Time *time"]],
    [0x0f, "syscall_cryp_state_alloc", ["unsigned long algo", "unsigned long op_mode", "unsigned long key1", "unsigned long key2", "uint32_t *state"]],
    [0x10, "syscall_cryp_state_copy", ["unsigned long dst", "unsigned long src"]],
    [0x11, "syscall_cryp_state_free", ["unsigned long state"]],
    [0x12, "syscall_hash_init", ["unsigned long state", "const void *iv", "size_t iv_len"]],
    [0x13, "syscall_hash_update", ["unsigned long state", "const void *chunk", "size_t chunk_size"]],
    [0x14, "syscall_hash_final", ["unsigned long state", "const void *chunk", "size_t chunk_size", "void *hash", "uint64_t *hash_len"]],
    [0x15, "syscall_cipher_init", ["unsigned long state", "const void *iv", "size_t iv_len"]],
    [0x16, "syscall_cipher_update", ["unsigned long state", "const void *src", "size_t src_len", "void *dest", "uint64_t *dest_len"]],
    [0x17, "syscall_cipher_final", ["unsigned long state", "const void *src", "size_t src_len", "void *dest", "uint64_t *dest_len"]],
    [0x18, "syscall_cryp_obj_get_info", ["unsigned long obj", "TEE_ObjectInfo *info"]],
    [0x19, "syscall_cryp_obj_restrict_usage", ["unsigned long obj", "unsigned long usage"]],
    [0x1a, "syscall_cryp_obj_get_attr", ["unsigned long obj", "unsigned long attr_id", "void *buffer", "uint64_t *size"]],
    [0x1b, "syscall_cryp_obj_alloc", ["unsigned long obj_type", "unsigned long max_key_size", "uint32_t *obj"]],
    [0x1c, "syscall_cryp_obj_close", ["unsigned long obj"]],
    [0x1d, "syscall_cryp_obj_reset", ["unsigned long obj"]],
    [0x1e, "syscall_cryp_obj_populate", ["unsigned long obj", "struct utee_attribute *attrs", "unsigned long attr_count"]],
    [0x1f, "syscall_cryp_obj_copy", ["unsigned long dst_obj", "unsigned long src_obj"]],
    [0x20, "syscall_cryp_derive_key", ["unsigned long state", "const struct utee_attribute *params", "unsigned long param_count", "unsigned long derived_key"]],
    [0x21, "syscall_cryp_random_number_generate", ["void *buf", "size_t blen"]],
    [0x22, "syscall_authenc_init", ["unsigned long state", "const void *nonce", "size_t nonce_len", "size_t tag_len", "size_t aad_len", "size_t payload_len"]],
    [0x23, "syscall_authenc_update_aad", ["unsigned long state", "const void *aad_data", "size_t aad_data_len"]],
    [0x24, "syscall_authenc_update_payload", ["unsigned long state", "const void *src_data", "size_t src_len", "void *dest_data", "uint64_t *dest_len"]],
    [0x25, "syscall_authenc_enc_final", ["unsigned long state", "const void *src_data", "size_t src_len", "void *dest_data", "uint64_t *dest_len", "void *tag", "uint64_t *tag_len"]],
    [0x26, "syscall_authenc_dec_final", ["unsigned long state", "const void *src_data", "size_t src_len", "void *dest_data", "uint64_t *dest_len", "const void *tag", "uint64_t *tag_len"]],
    [0x27, "syscall_asymm_operate", ["unsigned long state", "const struct utee_attribute *usr_params", "size_t num_params", "const void *src_data", "size_t src_len", "void *dest_data", "uint64_t *dest_len"]],
    [0x28, "syscall_asymm_verify", ["unsigned long state", "const struct utee_attribute *usr_params", "size_t num_params", "const void *data", "size_t data_len", "const void *sig", "size_t sig_len"]],
    [0x29, "syscall_storage_obj_open", ["unsigned long storage_id", "void *object_id", "size_t object_id_len", "unsigned long flags", "uint32_t *obj"]],
    [0x2a, "syscall_storage_obj_create", ["unsigned long storage_id", "void *object_id", "size_t object_id_len", "unsigned long flags", "unsigned long attr", "void *data", "size_t len", "uint32_t *obj"]],
    [0x2b, "syscall_storage_obj_del", ["unsigned long obj"]],
    [0x2c, "syscall_storage_obj_rename", ["unsigned long obj", "void *object_id", "size_t object_id_len"]],
    [0x2d, "syscall_storage_alloc_enum", ["uint32_t *obj_enum"]],
    [0x2e, "syscall_storage_free_enum", ["nsigned long obj_enum"]],
    [0x2f, "syscall_storage_reset_enum", ["unsigned long obj_enum"]],
    [0x30, "syscall_storage_start_enum", ["unsigned long obj_enum", "unsigned long storage_id"]],
    [0x31, "syscall_storage_next_enum", ["unsigned long obj_enum", "TEE_ObjectInfo *info", "void *obj_id", "uint64_t *len"]],
    [0x32, "syscall_storage_obj_read", ["unsigned long obj", "void *data", "size_t len", "uint64_t *count"]],
    [0x33, "syscall_storage_obj_write", ["unsigned long obj", "void *data", "size_t len"]],
    [0x34, "syscall_storage_obj_trunc", ["unsigned long obj, size_t len"]],
    [0x35, "syscall_storage_obj_seek", ["unsigned long obj", "int32_t offset", "unsigned long whence"]],
    [0x36, "syscall_obj_generate_key", ["unsigned long obj", "unsigned long key_size", "const struct utee_attribute *params", "unsigned long param_count"]],
    [0x37, "syscall_not_supported", []],
    [0x38, "syscall_not_supported", []],
    [0x39, "syscall_not_supported", []],
    [0x3a, "syscall_not_supported", []],
    [0x3b, "syscall_not_supported", []],
    [0x3c, "syscall_not_supported", []],
    [0x3d, "syscall_not_supported", []],
    [0x3e, "syscall_not_supported", []],
    [0x3f, "syscall_not_supported", []],
    [0x40, "syscall_not_supported", []],
    [0x41, "syscall_not_supported", []],
    [0x42, "syscall_not_supported", []],
    [0x43, "syscall_not_supported", []],
    [0x44, "syscall_not_supported", []],
    [0x45, "syscall_not_supported", []],
    [0x46, "syscall_cache_operation", ["void *va, size_t len", "unsigned long op"]],
]


# ARM/ARM64 OP-TEE ldelf (at secure world)
# - core/include/tee/tee_svc.h
# - core/include/kernel/ldelf_syscalls.h
arm_ldelf_syscall_list = [ # noqa: F841
    [0x00, "syscall_sys_return", ["unsigned long ret"]],
    [0x01, "syscall_log", ["const void *buf", "size_t len"]],
    [0x02, "syscall_panic", ["unsigned long code"]],
    [0x03, "ldelf_syscall_map_zi", ["vaddr_t *va", "size_t num_bytes", "size_t pad_begin", "size_t pad_end", "unsigned long flags"]],
    [0x04, "ldelf_syscall_unmap", ["vaddr_t va", "size_t num_bytes"]],
    [0x05, "ldelf_syscall_open_bin", ["const TEE_UUID *uuid", "size_t uuid_size", "uint32_t *handle"]],
    [0x06, "ldelf_syscall_close_bin", ["unsigned long handle"]],
    [0x07, "ldelf_syscall_map_bin", ["vaddr_t *va", "size_t num_bytes", "unsigned long handle", "size_t offs_bytes", "size_t pad_begin", "size_t pad_end", "unsigned long flags"]],
    [0x08, "ldelf_syscall_copy_from_bin", ["void *dst", "size_t offs", "size_t num_bytes", "unsigned long handle"]],
    [0x09, "ldelf_syscall_set_prot", ["unsigned long va", "size_t num_bytes", "unsigned long flags"]],
    [0x0a, "ldelf_syscall_remap", ["unsigned long old_va", "addr_t *new_va", "size_t num_bytes", "size_t pad_begin", "size_t pad_end"]],
    [0x0b, "ldelf_syscall_gen_rnd_num", ["void *buf", "size_t num_bytes"]],
]


# x86_16 FreeDOS int 0x21
# https://en.wikipedia.org/wiki/DOS_API
# https://stanislavs.org/helppc/int_21.html
# http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf
x86_16_dos_syscall_list = [
    # nr, syscall name, return registers, args, arg registers
    # 1.0+
    [0x00, "ProgramTerminate", [], [], []],
    [0x01, "CharacterInput", ["$al"], [], []],
    [0x02, "CharacterOutput", [], ["character"], ["$dl"]],
    [0x03, "AuxiliaryInput", ["$al"], [], []],
    [0x04, "AuxiliaryOutput", [], ["character"], ["$dl"]],
    [0x05, "PrinterOutput", [], ["character"], ["$dl"]],
    [0x06, "DirectConsoleIo", ["$al", "$eflags.zf"], ["character"], ["$dl"]],
    [0x07, "DirectStdinInputNoEcho", ["$al"], [], []],
    [0x08, "ConsoleInputNoEcho", ["$al"], [], []],
    [0x09, "DisplayString", [], ["string"], ["$ds:$dx"]],
    [0x0a, "BufferedKeyboardInput", [], ["buffer"], ["$ds:$dx"]],
    [0x0b, "GetInputStatus", ["$al"], [], []],
    [0x0c, "FlushInputBufferAndInput", ["$al"], ["function"], ["$al"]],
    [0x0d, "DiskReset", [], [], []],
    [0x0e, "SetDefaultDrive", ["$al"], ["drive_number"], ["$dl"]],
    [0x0f, "OpenFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x10, "CloseFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x11, "FindFirstFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x12, "FindNextFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x13, "DeleteFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x14, "SequentialRead", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x15, "SequentialWrite", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x16, "CreateFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x17, "RenameFile", ["$al"], ["FCB"], ["$ds:$dx"]],
    # 0x18: reserved
    [0x19, "GetDefaultDrive", ["$al"], [], []],
    [0x1a, "SetDiskTransferAddress", [], ["DTA"], ["$ds:$dx"]],
    [0x1b, "GetAllocationInfoForDefaultDrive", ["$al", "$cx", "$dx", "$ds:$bx"], [], []],
    [0x1c, "GetAllocationInfoForSpecifiedDrive", ["$al", "$cx", "$dx", "$ds:$bx"], ["drive_number"], ["$dl"]],
    # 0x1d: reserved
    # 0x1e: reserved
    [0x1f, "GetDiskParameterBlockForDefaultDrive", ["$al"], ["drive_number"], ["$dl"]],
    # 0x20: reserved
    [0x21, "RandomRead", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x22, "RandomWrite", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x23, "GetFileSizeInRecords", ["$al"], ["FCB"], ["$ds:$dx"]],
    [0x24, "SetRandomRecordNumber", [], ["FCB"], ["$ds:$dx"]],
    [0x25, "SetInterruptVector", [], ["interrupt_number", "handler"], ["$al", "$ds:$dx"]],
    [0x26, "CreatePSP", [], ["segment_number"], ["$dx"]],
    [0x27, "RandomBlockRead", ["$al", "$cx"], ["FCB", "record_count"], ["$ds:$dx", "$cx"]],
    [0x28, "RandomBlockWrite", ["$al", "$cx"], ["FCB", "record_count"], ["$ds:$dx", "$cx"]],
    [0x29, "ParseFilename", ["$al", "$ds:$si", "$es:$di"], ["control", "string", "buffer"], ["$al", "$ds:$si", "$es:$di"]],
    [0x2a, "GetDate", ["$al", "$cx", "$dh", "$dl"], [], []],
    [0x2b, "SetDate", ["$al"], ["year", "month", "day"], ["$cx", "$dh", "$dl"]],
    [0x2c, "GetTime", ["$ch", "$cl", "$dh", "$dl"], [], []],
    [0x2d, "SetTime", ["$al"], ["hour", "minutes", "seconds", "hundredths"], ["$ch", "$cl", "$dh", "$dl"]],
    [0x2e, "SetVerifyFlag", [], ["verify_flag", "0"], ["$al", "$dl"]],
    # 2.0+
    [0x2f, "GetDiskTransferAddress", ["$es:$bx"], [], []],
    [0x30, "GetDosVersion", ["$al", "$ah", "$bh", "$bl", "$cx"], [], []],
    [0x31, "TerminateAndStayResident", [], ["exit_code", "program_size"], ["$al", "$dx"]],
    [0x32, "GetDiskParameterBlock", ["$al", "$ds:$bx"], ["drive"], ["$dl"]],
    [0x33, "GetOrSetCtrlBreak", ["$al", "$dl"], ["subfunction", "value"], ["$al", "$dl"]],
    [0x34, "GetDosCriticalFlagPointer", ["$es:$bx"], [], []],
    [0x35, "GetInterruptVector", ["$es:$bx"], ["interrupt_number"], ["$al"]],
    [0x36, "GetFreeDiskSpace", ["$ax", "$bx", "$cx", "$dx"], ["drive_number"], ["$dl"]],
    [0x37, "GetOrSetSwitchCharacter", ["$al", "$dl"], ["subfunction", "value"], ["$al", "$dl"]],
    [0x38, "GetOrSetCountryInfo", ["$ax", "$bx", "$ds:$dx"], ["subfunction", "country_code", "buffer"], ["$al", "$bx", "$ds:dx"]],
    [0x39, "CreateSubDirectory", ["$ax"], ["pathname"], ["$ds:$dx"]],
    [0x3a, "RemoveSubDirectory", ["$ax"], ["pathname"], ["$ds:$dx"]],
    [0x3b, "ChangeCurrentDirectory", ["$ax"], ["pathname"], ["$ds:$dx"]],
    [0x3c, "CreateFile", ["$ax"], ["pathname", "attribute"], ["$ds:$dx", "$cx"]],
    [0x3d, "OpenFile", ["$ax"], ["mode", "pathname"], ["$al", "$ds:$dx"]],
    [0x3e, "CloseFile", ["$ax"], ["handle"], ["$bx"]],
    [0x3f, "ReadFileOrDevice", ["$ax"], ["handle", "size"], ["$bx", "$cx", "$ds:$dx"]],
    [0x40, "WriteFileOrDevice", ["$ax"], ["handle", "size", "buffer"], ["$bx", "$cx", "$ds:$dx"]],
    [0x41, "DeleteFile", ["$ax"], ["pathname"], ["$ds:$dx"]],
    [0x42, "SeekFile", ["$dx", "$ax"], ["origin", "handle", "move_size_high", "move_size_low"], ["$al", "$bx", "$cx", "$dx"]],
    [0x43, "GetOrSetFileAttributes", ["$ax", "$cx"], ["subfunction", "pathname", "attribute"], ["$al", "$ds:$dx", "$cx"]],
    [0x44, "IoControlForDevices", ["$ax", "$dx"], ["subfunction", "arg1", "arg2", "arg3"], ["$al", "$bx", "$cx", "$ds:$dx"]],
    [0x45, "DuplicateHandle", ["$ax"], ["handle"], ["$bx"]],
    [0x46, "RedirectHandle", ["$ax"], ["old_handle", "new_handle"], ["$bx", "$cx"]],
    [0x47, "GetCurrentDirectory", ["$ds:$si", "$ax"], ["drive_number", "buffer"], ["$dl", "$ds:$si"]],
    [0x48, "AllocateMemory", ["$ax", "$bx"], ["block_size"], ["$bx"]],
    [0x49, "ReleaseMemory", ["$ax"], ["segment"], ["$es"]],
    [0x4a, "ReallocateMemory", ["$ax", "$bx"], ["new_block_size", "segment"], ["$bx", "$es"]],
    [0x4b, "ExecuteProgram", ["$ax", "$es:$bx"], ["subfunction", "pathname", "parameter"], ["$al", "$ds:$dx", "$es:$bx"]],
    [0x4c, "TerminateWithReturnCode", [], ["return_code"], ["$al"]],
    [0x4d, "GetProgramReturnCode", ["$ah", "$al"], [], []],
    [0x4e, "FindFirstFile", ["$ax"], ["pathname", "attribute"], ["$ds:$dx", "$cx"]], # DTA omitted
    [0x4f, "FindNextFile", ["$ax"], ["pathname"], ["$ds:$dx"]], # DTA omitted
    [0x50, "SetCurrentPSP", [], ["segment"], ["$bx"]],
    [0x51, "GetCurrentPSP", ["$bx"], [], []],
    [0x52, "GetListOfLists", ["$es:$bx"], [], []],
    [0x53, "CreateDiskParameterBlock", ["$es:$bp"], ["bios_parameter", "buffer"], ["$ds:si", "$es:$bp"]],
    [0x54, "GetVerifyFlag", ["$al"], [], []],
    [0x55, "CreateProgramPSP", [], ["segment", "size"], ["$dx", "$si"]],
    [0x56, "RenameFile", ["$ax"], ["old_pathname", "new_pathname"], ["$ds:$dx", "$es:$di"]],
    [0x57, "GetOrSetFileDateAndTime", ["$ax", "$cx", "$dx"], ["subfunction", "handle", "time", "date", "buffer"], ["$al", "$bx", "$cx", "$dx", "$es:$di"]],
    # 2.11+
    [0x58, "GetOrSetAllocationStrategy", ["$ax"], ["subfunction", "strategy"], ["$al", "$bx"]],
    # 3.0+
    [0x59, "GetExtendedErrorInfo", ["$ax", "$bh", "$bl", "$ch"], ["0"], ["$bx"]],
    [0x5a, "CreateTempFile", ["$ax", "$ds:$dx"], ["pathname", "attribute"], ["$ds:$dx", "$cx"]],
    [0x5b, "CreateNewFile", ["$ax"], ["pathname", "attribute"], ["$ds:$dx", "$cx"]],
    [0x5c, "LockOrUnlockFile", ["$ax"], ["subfunction", "handle", "offset_high", "offset_low", "length_high", "length_low"], ["$al", "$bx", "$cx", "$dx", "$si", "$di"]],
    [0x5d, "FileSharingFunctions", ["$ds:$si"], ["subfunction", "arg1"], ["$al", "$ds:$dx"]],
    [0x5e, "NetworkFunctions", ["$ax"], ["subfunction"], ["$al"]], # too complicated
    [0x5f, "NetworkRedirectionFunctions", ["$ax"], ["subfunction"], ["$al"]], # too complicated
    [0x60, "QualifyFilename", ["$es:$di", "$ah"], ["pathname", "buffer"], ["$ds:$si", "$es:$di"]],
    # 0x61: reserved
    [0x62, "GetCurrentPSP", ["$bx"], [], []],
    [0x63, "GetLeadByteTable", ["$ax", "$ds:$si", "$dl"], ["subfunction", "flag"], ["$al", "$dl"]],
    # 3.2+
    [0x64, "SetDeviceDriverLookAhead", ["$dl"], ["subfunction", "arg1"], ["$al", "$dl"]],
    # 3.3+
    [0x65, "GetExtendedCountryInfo", ["$ax"], ["subfunction"], ["$al"]], # too complicated
    [0x66, "GetOrSetGlobalCodePage", ["$ax", "$bx", "$cx"], ["subfunction", "active_codepage", "system_codepage"], ["$al", "$bx", "$dx"]],
    [0x67, "SetHandleCount", ["$ax"], ["max_handle_count"], ["$bx"]],
    [0x68, "CommitFile", ["$ax"], ["handle"], ["$bx"]],
    # 4.0+
    [0x69, "GetOrSetMediaId", ["$ax", "$ds:$dx"], ["subfunction", "drive_number", "buffer"], ["$al", "$bl", "$ds:$dx"]],
    # 0x6a: reserved
    # 0x6b: reserved
    [0x6c, "ExtendedOpenCreateFile", ["$ax", "$cx"], ["0", "mode", "attribute", "control", "spec"], ["$al", "$bx", "$cx", "$dx", "$ds:$si"]],
]

class Syscall:
    """A collection of utility functions that are related to syscall tables."""

    @staticmethod
    @Cache.cache_this_session
    def parse_common_syscall_defs():
        """Parse and return a common definition of a syscall, common to all architectures."""
        sc_defs = [
            syscall_defs,
            syscall_defs_compat,
        ]
        dic = {}
        for defs in sc_defs:
            for line in defs.splitlines():
                if line == "":
                    continue
                if line.startswith("#"):
                    continue
                # ignore `!`
                m = re.search(r"asmlinkage\s+(?:long|ssize_t)\s+(\S+)\((.+?)\);", line)
                if not m:
                    continue
                name, args = m.group(1), m.group(2)
                args = [x.strip() for x in args.split(",")]
                if name in dic:
                    err("Duplicate: {:s}".format(name))
                    raise
                if len(args) == 1 and args[0] == "void":
                    dic[name] = []
                else:
                    dic[name] = args
        return dic

    @staticmethod
    def parse_syscall_table_defs(table_defs):
        """Parse and return syscall table defines for a specified architecture."""
        table = []
        for line in table_defs.splitlines():
            if line == "":
                continue
            if line.startswith("#"):
                continue
            entry = line.split()
            if len(entry) == 3: # it is unimplemented
                continue
            entry[0] = int(entry[0])
            table.append(entry)
        return table

    @staticmethod
    @Cache.cache_this_session
    def make_syscall_table(arch, mode):
        # Late imports: gef.arch.* modules import gdb at top level.
        from gef.arch.alpha import ALPHA
        from gef.arch.arc import ARC, ARC64, ARCv3
        from gef.arch.arm import AARCH64, ARM
        from gef.arch.cris import CRIS
        from gef.arch.csky import CSKY
        from gef.arch.hppa import HPPA, HPPA64
        from gef.arch.loongarch64 import LOONGARCH64
        from gef.arch.m68k import M68K
        from gef.arch.microblaze import MICROBLAZE
        from gef.arch.mips import MIPS, MIPS64, MIPSN32
        from gef.arch.nios2 import NIOS2
        from gef.arch.or1k import OR1K
        from gef.arch.ppc import PPC, PPC64
        from gef.arch.riscv import RISCV, RISCV64
        from gef.arch.s390x import S390X
        from gef.arch.sh4 import SH4
        from gef.arch.sparc import SPARC, SPARC32PLUS, SPARC64
        from gef.arch.x86 import X86, X86_64
        from gef.arch.xtensa import XTENSA

        if arch == "X86" and mode == "64":
            return_register = X86_64.return_register
            args_register = X86_64.syscall_parameters
            syscall_list = SyscallX86_64.make_syscall_list()

        elif arch == "X86" and mode == "Emulated-32":
            return_register = X86.return_register
            args_register = X86.syscall_parameters
            syscall_list = SyscallX86_32Emulated.make_syscall_list()

        elif arch == "X86" and mode == "Native-32":
            return_register = X86.return_register
            args_register = X86.syscall_parameters
            syscall_list = SyscallX86_32Native.make_syscall_list()

        elif arch == "X86" and mode == "16":
            syscall_list = []
            return_register = {}
            args_register = {}
            for nr, name, ret_regs, args, arg_regs in x86_16_dos_syscall_list:
                syscall_list.append([nr, name, args])
                return_register[nr] = ret_regs
                args_register[nr] = arg_regs

        elif arch == "ARM64" and mode == "ARM":
            return_register = AARCH64.return_register
            args_register = AARCH64.syscall_parameters
            syscall_list = SyscallARM64.make_syscall_list()

        elif arch == "ARM" and mode == "Emulated-32":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = SyscallARM32Emulated.make_syscall_list() # only support EABI

        elif arch == "ARM" and mode == "Native-32":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = SyscallARM32Native.make_syscall_list() # only support EABI

        elif arch == "ARM64" and mode == "Secure-World":
            return_register = AARCH64.return_register
            args_register = AARCH64.syscall_parameters + ["$x6"] # OPTEE uses 7 args
            syscall_list = arm_OPTEE_syscall_list.copy()

        elif arch == "ARM" and mode == "Secure-World":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = arm_OPTEE_syscall_list.copy()

        elif arch == "MIPS" and mode == "32":
            return_register = MIPS.return_register
            args_register = MIPS.syscall_parameters
            syscall_list = SyscallMIPS32.make_syscall_list()

        elif arch == "MIPS" and mode == "n32":
            return_register = MIPSN32.return_register
            args_register = MIPSN32.syscall_parameters
            syscall_list = SyscallMIPSN32.make_syscall_list()

        elif arch == "MIPS" and mode == "64":
            return_register = MIPS64.return_register
            args_register = MIPS64.syscall_parameters
            syscall_list = SyscallMIPS64.make_syscall_list()

        elif arch == "PPC" and mode == "32":
            return_register = PPC.return_register
            args_register = PPC.syscall_parameters
            syscall_list = SyscallPPC32.make_syscall_list()

        elif arch == "PPC" and mode == "64":
            return_register = PPC64.return_register
            args_register = PPC64.syscall_parameters
            syscall_list = SyscallPPC64.make_syscall_list()

        elif arch == "SPARC" and mode == "32":
            return_register = SPARC.return_register
            args_register = SPARC.syscall_parameters
            syscall_list = SyscallSPARC32.make_syscall_list()

        elif arch == "SPARC" and mode == "32PLUS":
            return_register = SPARC32PLUS.return_register
            args_register = SPARC32PLUS.syscall_parameters
            syscall_list = SyscallSPARC32.make_syscall_list() # same sparc32

        elif arch == "SPARC" and mode == "64":
            return_register = SPARC64.return_register
            args_register = SPARC64.syscall_parameters
            syscall_list = SyscallSPARC64.make_syscall_list()

        elif arch == "RISCV" and mode == "32":
            return_register = RISCV.return_register
            args_register = RISCV.syscall_parameters
            syscall_list = SyscallRISCV32.make_syscall_list()

        elif arch == "RISCV" and mode == "64":
            return_register = RISCV64.return_register
            args_register = RISCV64.syscall_parameters
            syscall_list = SyscallRISCV64.make_syscall_list()

        elif arch == "S390X" and mode == "64":
            return_register = S390X.return_register
            args_register = S390X.syscall_parameters
            syscall_list = SyscallS390X.make_syscall_list()

        elif arch == "SH4" and mode == "SH4":
            return_register = SH4.return_register
            args_register = SH4.syscall_parameters
            syscall_list = SyscallSH4.make_syscall_list()

        elif arch == "M68K" and mode == "32":
            return_register = M68K.return_register
            args_register = M68K.syscall_parameters
            syscall_list = SyscallM68K.make_syscall_list()

        elif arch == "ALPHA" and mode == "ALPHA":
            return_register = ALPHA.return_register
            args_register = ALPHA.syscall_parameters
            syscall_list = SyscallALPHA.make_syscall_list()

        elif arch == "HPPA" and mode == "32":
            return_register = HPPA.return_register
            args_register = HPPA.syscall_parameters
            syscall_list = SyscallHPPA32.make_syscall_list()

        elif arch == "HPPA" and mode == "64":
            return_register = HPPA64.return_register
            args_register = HPPA64.syscall_parameters
            syscall_list = SyscallHPPA64.make_syscall_list()

        elif arch == "OR1K" and mode == "OR1K":
            return_register = OR1K.return_register
            args_register = OR1K.syscall_parameters
            syscall_list = SyscallOR1K.make_syscall_list()

        elif arch == "NIOS2" and mode == "NIOS2":
            return_register = NIOS2.return_register
            args_register = NIOS2.syscall_parameters
            syscall_list = SyscallNIOS2.make_syscall_list()

        elif arch == "MICROBLAZE" and mode == "MICROBLAZE":
            return_register = MICROBLAZE.return_register
            args_register = MICROBLAZE.syscall_parameters
            syscall_list = SyscallMICROBLAZE.make_syscall_list()

        elif arch == "XTENSA" and mode == "XTENSA":
            return_register = XTENSA.return_register
            args_register = XTENSA.syscall_parameters
            syscall_list = SyscallXTENSA.make_syscall_list()

        elif arch == "CRIS" and mode == "CRIS":
            return_register = CRIS.return_register
            args_register = CRIS.syscall_parameters
            syscall_list = SyscallCRIS.make_syscall_list()

        elif arch == "LOONGARCH" and mode == "64":
            return_register = LOONGARCH64.return_register
            args_register = LOONGARCH64.syscall_parameters
            syscall_list = SyscallLOONGARCH64.make_syscall_list()

        elif arch == "ARC" and mode in ["32v2", "32"]:
            return_register = ARC.return_register
            args_register = ARC.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("32")

        elif arch == "ARC" and mode in ["32v3"]:
            return_register = ARCv3.return_register
            args_register = ARCv3.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("32")

        elif arch == "ARC" and mode in ["64v3", "64"]:
            return_register = ARC64.return_register
            args_register = ARC64.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("64")

        elif arch == "CSKY" and mode == "CSKY":
            return_register = CSKY.return_register
            args_register = CSKY.syscall_parameters
            syscall_list = SyscallCSKY.make_syscall_list()

        else:
            return None

        Table = collections.namedtuple("Table", "arch mode nr_table name_table")
        syscall_table = Table(arch, mode, {}, {})

        # example:
        #   syscall_table.arch: 'X86'
        #   syscall_table.mode: '64'
        #   syscall_table.nr_table[0].nr: 0
        #   syscall_table.nr_table[0].name: 'read'
        #   syscall_table.nr_table[0].ret_regs: ['$rax']
        #   syscall_table.nr_table[0].arg_regs: ['$rdi', '$rsi', ...]
        #   syscall_table.nr_table[0].args_full: ['unsigned int fd', ...]
        #   syscall_table.nr_table[0].args: ['fd', ...]
        #   syscall_table.nr_table[1] ...
        #   syscall_table.name_table["read"].nr: 0
        #   syscall_table.name_table["read"].name: 'read'
        #   syscall_table.name_table["read"].ret_regs: ['$rax']
        #   syscall_table.name_table["read"].arg_regs: ['$rdi', '$rsi', ...]
        #   syscall_table.name_table["read"].args_full: ['unsigned int fd', ...]
        #   syscall_table.name_table["read"].args: ['fd', ...]
        #   syscall_table.name_table["write"] ...
        Entry = collections.namedtuple("Entry", "nr name ret_regs arg_regs args_full args")
        for nr, name, args_full in sorted(syscall_list, key=lambda x: x[0]):
            # make entry
            args = [re.split(r" |\*", p)[-1] for p in args_full]
            if (arch, mode) == ("X86", "16"):
                entry = Entry(nr, name, return_register[nr], args_register[nr], args_full, args)
            else:
                entry = Entry(nr, name, [return_register], args_register[:len(args)], args_full, args)
            # nr_table
            syscall_table.nr_table[nr] = entry
            # name_table
            if name not in syscall_table.name_table:
                syscall_table.name_table[name] = entry
        return syscall_table

    @classmethod
    def get_syscall_table(cls, arch=None, mode=None):

        if arch is None and mode is None :
            # Late imports: gef.core.process imports gdb at top level.
            from gef.core.process import is_arm32, is_arm64, is_emulated32, \
                is_in_secure, is_x86_32, is_x86_64

            if is_x86_64():
                arch, mode = "X86", "64"
            elif is_x86_32():
                if is_emulated32():
                    arch, mode = "X86", "Emulated-32"
                else:
                    arch, mode = "X86", "Native-32"
            elif is_arm64():
                if is_in_secure():
                    arch, mode = "ARM64", "Secure-World"
                else:
                    arch, mode = "ARM64", "ARM"
            elif is_arm32():
                if is_in_secure():
                    arch, mode = "ARM", "Secure-World"
                elif is_emulated32():
                    arch, mode = "ARM", "Emulated-32"
                else:
                    arch, mode = "ARM", "Native-32"
            elif runtime.current_arch:
                arch = runtime.current_arch.arch
                mode = runtime.current_arch.mode
            else:
                arch, mode = None, None

        if arch in ["ARM", "ARM64"] and mode == "S":
            mode = "Secure-World"
        if arch in ["X86", "ARM"] and mode == "32":
            mode = "Emulated-32"
        elif arch in ["X86", "ARM"] and mode == "N32":
            mode = "Native-32"

        return cls.make_syscall_table(arch, mode)


class SyscallX86_64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_64.c
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "compat_sys_x32_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/x86/kernel/sys_x86_64.c
        "sys_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x64_syscall_tbl)
        syscall_list = []
        __X32_SYSCALL_BIT = 0x4000_0000
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            if abi not in ["common", "64", "x32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                if abi in ["common", "64"]:
                    syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                if abi in ["common", "x32"]:
                    syscall_list.append([nr + __X32_SYSCALL_BIT, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            if abi in ["common", "64"]:
                syscall_list.append([nr, name, sc_def[func]])
            if abi in ["common", "x32"]:
                syscall_list.append([nr + __X32_SYSCALL_BIT, name, sc_def[func]])
        return syscall_list


class SyscallX86_32Emulated(Syscall):
    arch_specific_dic = {
        "compat_sys_sigreturn": [], # arch/x86/ia32/ia32_signal.c
        "compat_sys_rt_sigreturn": [], # arch/x86/ia32/ia32_signal.c
        "compat_sys_old_getrlimit": [
            "unsigned int resource", "struct compat_rlimit *rlim",
        ], # kernel/sys.c
        "compat_sys_ia32_mmap": [
            "struct mmap_arg_struct32 __user *arg",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "compat_sys_ia32_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls_val", "int __user *child_tidptr",
        ], # arch/x86/kernel/sys_ia32.c (CONFIG_CLONE_BACKWARDS)
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_ia32_pread64": [
            "unsigned int fd", "char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_truncate64": [
            "const char __user *filename", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_ftruncate64": [
            "unsigned int fd", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_stat64": [
            "const char __user *filename", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_lstat64": [
            "const char __user *filename", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_fstat64": [
            "unsigned long fd", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_readahead": [
            "int fd", "unsigned int off_lo", "unsigned int off_high", "size_t count",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_set_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_get_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_ia32_fadvise64": [
            "int fd", "unsigned int offset_lo", "unsigned int offset_hi", "size_t len", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fadvise64_64": [
            "int fd", "__u32 offset_low", "__u32 offset_high", "__u32 len_low", "__u32 len_high", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_fstatat64": [
            "unsigned int dfd", "const char __user *filename", "struct stat64 __user *statbuf", "int flag",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_sync_file_range": [
            "int fd", "unsigned int off_low", "unsigned int off_hi", "unsigned int n_low",
            "unsigned int n_hi", "unsigned int flags",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fallocate": [
            "int fd", "int mode", "unsigned int offset_lo", "unsigned int offset_hi",
            "unsigned int len_lo", "unsigned int len_hi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_64.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x86_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            if len(entry) == 5:
                nr, abi, name, _, func = entry # use compat
            else:
                nr, abi, name, func = entry[:4]
            if abi != "i386":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallX86_32Native(Syscall):
    arch_specific_dic = {
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "sys_vm86old": [
            "struct vm86_struct __user *user_vm86",
        ], # arch/x86/kernel/vm86_32.c
        "sys_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_vm86": [
            "unsigned long cmd", "unsigned long arg",
        ], # arch/x86/kernel/vm86_32.c
        "sys_ia32_pread64": [
            "unsigned int fd", "char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_truncate64": [
            "const char __user *filename", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_ftruncate64": [
            "unsigned int fd", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_readahead": [
            "int fd", "unsigned int off_lo", "unsigned int off_high", "size_t count",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_set_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_get_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_ia32_fadvise64": [
            "int fd", "unsigned int offset_lo", "unsigned int offset_hi", "size_t len", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fadvise64_64": [
            "int fd", "__u32 offset_low", "__u32 offset_high", "__u32 len_low", "__u32 len_high", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_sync_file_range": [
            "int fd", "unsigned int off_low", "unsigned int off_hi", "unsigned int n_low",
            "unsigned int n_hi", "unsigned int flags",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fallocate": [
            "int fd", "int mode", "unsigned int offset_lo", "unsigned int offset_hi",
            "unsigned int len_lo", "unsigned int len_hi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x86_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "i386":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARM64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn": [], # arch/arm64/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/arm64/kernel/sys.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/arm64/kernel/Makefile.syscalls
            if abi not in ["common", "64", "renameat", "rlimit", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARM32Emulated(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "compat_sys_aarch32_pread64": [
            "unsigned int fd", "char *buf", "size_t count", "u32 __pad", "arg_u32p(pos)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_pwrite64": [
            "unsigned int fd", "const char *buf", "size_t count", "u32 __pad", "arg_u32p(pos)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off_4k",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_truncate64": [
            "const char *path", "u32 __pad", "arg_u32p(length)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_ftruncate64": [
            "unsigned int fd", "u32 __pad", "arg_u32p(length)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_readahead": [
            "int fd", "u32 __pad", "arg_u32(offset)", "size_t count",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_statfs64": [
            "const char *pathname", "compat_size_t sz", "struct compat_statfs64 *buf",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fstatfs64": [
            "unsigned int fd", "compat_size_t sz", "struct compat_statfs64 *buf",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fadvise64_64": [
            "int fd", "int advice", "arg_u32p(offset)", "arg_u32p(len)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_sync_file_range2": [
            "int fd", "unsigned int flags", "arg_u32p(offset)", "arg_u32p(nbytes)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fallocate": [
            "int fd", "int mode", "arg_u32p(offset)", "arg_u32p(len)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_old_semctl": [
            "int semid", "int semnum", "int cmd", "int arg",
        ], # ipc/sem.c
        "compat_sys_old_msgctl": [
            "int msqid", "int cmd", "void *uptr",
        ], # ipc/msg.c
        "compat_sys_old_shmctl": [
            "int shmid", "int cmd", "void *uptr",
        ], # ipc/shm.c
        "compat_sys_sigreturn": [], # arch/arm64/kernel/signal32.c
        "compat_sys_rt_sigreturn": [], # arch/arm64/kernel/signal32.c
    }

    arch_specific_extra = [
        [0xf0002, "cacheflush", [
            "unsigned long start", "unsigned long end", "int flags",
        ]], # arch/arm64/kernel/sys_compat.c
        [0xf0005, "set_tls", [
            "unsigned long val",
        ]], # arch/arm64/kernel/sys_compat.c
    ]

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm_compat_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            if len(entry) == 5:
                nr, abi, name, _, func = entry # use compat
            else:
                nr, abi, name, func = entry[:4]
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])

        syscall_list += cls.arch_specific_extra
        return syscall_list


class SyscallARM32Native(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_sigreturn_wrapper": [], # arch/arm/kernel/entry-common.S
        "sys_rt_sigreturn_wrapper": [], # arch/arm/kernel/entry-common.S
        "sys_statfs64_wrapper": [
            "const char __user *path", "size_t sz", "struct statfs64 __user *buf",
        ], # arch/arm/kernel/entry-common.S
        "sys_fstatfs64_wrapper": [
            "unsigned int fd", "size_t sz", "struct statfs64 __user *buf",
        ], # arch/arm/kernel/entry-common.S
        "sys_arm_fadvise64_64": [
            "int fd", "int advice", "loff_t offset", "loff_t len",
        ], # arch/arm/kernel/sys_arm.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    arch_specific_extra = [
        [0xf0001, "breakpoint", []], # arch/arm/kernel/traps.c
        [0xf0002, "cacheflush", [
            "unsigned long start", "unsigned long end", "int flags",
        ]], # arch/arm/kernel/traps.c
        [0xf0003, "usr26", []], # arch/arm/kernel/traps.c
        [0xf0004, "usr32", []], # arch/arm/kernel/traps.c
        [0xf0005, "set_tls", [
            "unsigned long val",
        ]], # arch/arm/kernel/traps.c
        [0xf0006, "get_tls", []], # arch/arm/kernel/traps.c
    ]

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm_native_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use OABI
            if abi not in ["common", "eabi"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])

        syscall_list += cls.arch_specific_extra
        return syscall_list


class SyscallMIPS32(Syscall):
    arch_specific_dic = {
        "sys_syscall": ["..."], #
        "__sys_fork": [], #
        "sys_rt_sigreturn": [], # arch/mips/kernel/signal.c
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "sys_sigreturn": [], #
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_mips_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_sigsuspend": [
            "sigset_t __user *uset",
        ], # arch/mips/kernel/signal.c
        "sys_sigaction": [
            "int sig2", "const struct sigaction __user *act", "struct sigaction __user *oact",
        ], # arch/mips/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_o32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "o32":
                continue
            nr += 4000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMIPSN32(Syscall):
    arch_specific_dic = {
        "__sys_fork": [], #
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "compat_sys_old_shmctl": [
            "int shmid", "int cmd", "void *uptr",
        ], # ipc/shm.c
        "compat_sys_old_semctl": [
            "int semid", "int semnum", "int cmd", "int arg",
        ], # ipc/sem.c
        "compat_sys_old_msgctl": [
            "int msqid", "int cmd", "void *uptr",
        ], # ipc/msg.c
        "sys_32_personality": [
            "unsigned long personality",
        ], # arch/mips/kernel/linux32.c
        "sysn32_rt_sigreturn": [], # arch/mips/kernel/signal_n32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_n32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "n32":
                continue
            nr += 6000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMIPS64(Syscall):
    arch_specific_dic = {
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "__sys_fork": [], #
        "sys_rt_sigreturn": [], # arch/mips/kernel/signal.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_n64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "n64":
                continue
            nr += 5000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallPPC32(Syscall):
    arch_specific_dic = {
        "sys_sigreturn": [], # arch/powerpc/kernel/signal_32.c
        "sys_rt_sigreturn": [], # arch/powerpc/kernel/signal_32.c
        "sys_mmap": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_mmap2": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_swapcontext": [
            "struct ucontext __user *old_ctx", "struct ucontext __user *new_ctx", "long ctx_size",
        ], # arch/powerpc/kernel/signal_32.c
        "ppc_fadvise64_64": [
            "int fd", "int advice", "u32 offset_high", "u32 offset_low", "u32 len_high", "u32 len_low",
        ], # arch/poerpc/kernel/syscalls.c
        "sys_rtas": [
            "struct rtas_args __user *uargs",
        ], # arch/powerpc/include/asm/syscalls.h
        "sys_debug_setcontext": [
            "struct ucontext __user *ctx", "int ndbg", "struct sig_dbg_op __user *dbg",
        ], # arch/powerpc/kernel/signal_32.c
        "sys_subpage_prot": [
            "unsigned long addr", "unsigned long len", "u32 __user *map",
        ], # arch/powerpc/mm/book3s64/subpage_prot.c
        "sys_ppc_pread64": [
            "unsigned int fd", "char __user *ubuf", "compat_size_t count", "u32 reg6", "u32 pos1", "u32 pos2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "compat_size_t count", "u32 reg6", "u32 pos1", "u32 pos2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_readahead": [
            "int fd", "u32 r4", "u32 offset1", "u32 offset2", "u32 count",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_truncate64": [
            "const char __user *path", "u32 reg4", "unsigned long len1", "unsigned long len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_ftruncate64": [
            "unsigned int fd", "u32 reg4", "unsigned long len1", "unsigned long len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc32_fadvise64": [
            "int fd", "u32 unused", "u32 offset1", "u32 offset2", "size_t len", "int advice",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_fadvise64_64": [
            "int fd", "int advice", "u32 offset_high", "u32 offset_low", "u32 len_high", "u32 len_low",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_ppc_sync_file_range2": [
            "int fd", "unsigned int flags", "unsigned int offset1", "unsigned int offset2",
            "unsigned int nbytes1", "unsigned int nbytes2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_fallocate": [
            "int fd", "int mode", "u32 offset1", "u32 offset2", "u32 len1", "u32 len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(ppc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32", "nospu"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallPPC64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn": [], # arch/powerpc/kernel/signal_64.c
        "sys_mmap": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_mmap2": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_ppc64_personality": [
            "unsigned long personality",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_swapcontext": [
            "struct ucontext __user *old_ctx", "struct ucontext __user *new_ctx", "long ctx_size",
        ], # arch/powerpc/kernel/signal_64.c
        "sys_rtas": [
            "struct rtas_args __user *uargs",
        ], # arch/powerpc/include/asm/syscalls.h
        "sys_subpage_prot": [
            "unsigned long addr", "unsigned long len", "u32 __user *map",
        ], # arch/powerpc/mm/book3s64/subpage_prot.c
        "sys_switch_endian": [], # arch/powerpc/kernel/syscalls.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(ppc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64", "nospu"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSPARC32(Syscall):
    arch_specific_dic = {
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sunos_execv": [
            "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp",
        ], # arch/sparc/kernel/entry.S
        "sys_sparc_pipe": [], # arch/sparc/kernel/sys_sparc_32.c
        "sys_getpagesize": [], # arch/sparc/kernel/sys_sparc_32.c
        "sys_getdomainname": [
            "char __user *name", "int len"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_sparc_remap_file_pages": [
            "unsigned long start", "unsigned long size", "unsigned long prot",
            "unsigned long pgoff", "unsigned long flags",
        ], # kernel/sys_sparc_32.c
        "sys_sparc_sigaction": [
            "int, sig", "struct old_sigaction __user *act", "struct old_sigaction __user *oact",
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_sigreturn": [], # arch/sparc/kernel/syscalls.S
        "sys_rt_sigreturn": [], # arch/sparc/kernel/syscalls.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sparc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "sys_nis_syscall"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSPARC64(Syscall):
    arch_specific_dic = {
        "sparc_exit": [
            "int error_code",
        ], # arch/sparc/kernel/syscalls.S
        "sys_sparc_pipe": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys_memory_ordering": [
            "unsigned long model",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys64_execve": [
            "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp",
        ], # arch/sparc/kernel/syscalls.S
        "sys_getpagesize": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys_64_munmap": [
            "unsigned long addr", "size_t len",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_getdomainname": [
            "char __user *name", "int len"
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_utrap_install": [
            "utrap_entry_t type", "utrap_handler_t new_p", "utrap_handler_t new_d",
            "utrap_handler_t __user * old_p", "utrap_handler_t __user *old_d",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sparc_exit_group": [
            "int error_code",
        ], # arch/sparc/kernel/syscalls.S
        "sys_sparc64_personality": [
            "unsigned long personality",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_sparc_ipc": [
            "unsigned int call", "int first", "unsigned long second",
            "unsigned long third", "void __user *ptr", "long fifth",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_sparc_adjtimex": [
            "struct __kernel_timex __user *txc_p",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off"
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_64_mremap": [
            "unsigned long addr", "unsigned long old_len", "unsigned long new_len",
            "unsigned long flags", "unsigned long new_addr",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_sparc_clock_adjtime": [
            "const clockid_t which_clock", "struct __kernel_timex __user *txc_p",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_kern_features": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys64_execveat": [
            "int dfd", "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp", "int flags",
        ] ,# arch/sparc/kernel/syscalls.S
        "sys_rt_sigreturn": [
            "struct pt_regs *regs",
        ], # arch/sparc/kernel/signal_64.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sparc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "sys_nis_syscall"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallRISCV32(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/riscv/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/riscv/kernel/sys_riscv.c"
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_riscv_flush_icache": [
            "uintptr_t start", "uintptr_t end", "uintptr_t flags",
        ], # arch/riscv/kernel/sys_riscv.c
        "sys_riscv_hwprobe": [
            "struct riscv_hwprobe __user *pairs", "size_t pair_count", "size_t cpusetsize",
            "unsigned long __user *cpus", "unsigned int flags",
        ], # arch/riscv/kernel/sys_hwprobe.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(riscv32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/riscv/kernel/Makefile.syscalls
            if abi not in ["common", "32", "riscv", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallRISCV64(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/riscv/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/riscv/kernel/sys_riscv.c"
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_riscv_flush_icache": [
            "uintptr_t start", "uintptr_t end", "uintptr_t flags",
        ], # arch/riscv/kernel/sys_riscv.c
        "sys_riscv_hwprobe": [
            "struct riscv_hwprobe __user *pairs", "size_t pair_count", "size_t cpusetsize",
            "unsigned long __user *cpus", "unsigned int flags",
        ], # arch/riscv/kernel/sys_hwprobe.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(riscv64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/riscv/kernel/Makefile.syscalls
            if abi not in ["common", "64", "riscv", "rlimit", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallS390X(Syscall):
    arch_specific_dic = {
        "sys_s390_ipc": [
            "uint, call", "int first", "unsigned long second",
            "unsigned long third", "void __user *ptr",
        ], # arch/s390/kernel/syscall.c
        "sys_sigreturn": [], # arch/s390/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS2)
        "sys_s390_personality": [
            "unsigned int personality",
        ], # arch/s390/kernel/syscall.c
        "sys_rt_sigreturn": [], # arch/s390/kernel/signal.c
        "sys_s390_runtime_instr": [
            "int, command", "int signum",
        ], # arch/s390/kernel/runtime_instr.c
        "sys_s390_pci_mmio_write": [
            "unsigned long mmio_addr", "const void __user *user_buffer", "size_t length",
        ], # arch/s390/pci/pci_mmio.c
        "sys_s390_pci_mmio_read": [
            "unsigned long mmio_addr", "void __user *user_buffer", "size_t length",
        ], # arch/s390/pci/pci_mmio.c
        "sys_s390_guarded_storage": [
            "int command", "struct gs_cb __user *gs_cb",
        ], # arch/s390/kernel/guarded_storage.c
        "sys_s390_sthyi": [
            "unsigned long function_code", "void __user *buffer", "u64 __user *return_code",
            "unsigned long flags",
        ], # arch/s390/kernel/sthyi.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(s390x_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "-"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSH4(Syscall):
    arch_specific_dic = {
        "sys_sh_pipe": [], # arch/sh/kernel/sys_sh32.c
        "old_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "int fd", "unsigned long off",
        ], # arch/sh/kernel/sys_sh.c
        "sys_sigreturn": [], # arch/sh/kernel/signal_32.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long len", "int op",
        ], # arch/sh/kernel/sys_sh.c
        "sys_rt_sigreturn": [], # arch/sh/kernel/signal_32.c
        "sys_pread_wrapper": [
            "unsigned int fd", "char __user *buf", "size_t count", "long dummy", "loff_t pos",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_pwrite_wrapper": [
            "unsigned int fd", "const char __user *buf", "size_t count", "long dummy", "loff_t pos",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/sh/kernel/sys_sh.c
        "sys_fadvise64_64_wrapper": [
            "int fd", "u32 offset0", "u32 offset1", "u32 len0", "u32 len1", "int advice",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_sh_sync_file_range6": [
            "int fd", "u64 offset", "u64 nbytes", "unsigned int flags",
        ], # sh/kernel/sys_sh32.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sh4_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallM68K(Syscall):
    arch_specific_dic = {
        "__sys_fork": [], # kernel/fork.c
        "sys_sigreturn": [], # arch/m68k/kernel/entry.S
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_cacheflush": [
            "unsigned long addr", "int scope", "int cache", "unsigned long len",
        ], #
        "sys_getpagesize": [], # arch/m68k/kernel/sys_m68k.c
        "sys_rt_sigreturn": [], # arch/m68k/kernel/entry.S
        "__sys_vfork": [], # kernel/fork.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_get_thread_area": [], # arch/m68k/kernel/sys_m68k.c
        "sys_set_thread_area": [
            "unsigned long tp",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_atomic_cmpxchg_32": [
            "unsigned long newval", "int oldval", "int d3", "int d4", "int d5",
            "unsigned long __user *mem",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_atomic_barrier": [], # arch/m68k/kernel/sys_m68k.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(m68k_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallALPHA(Syscall):
    arch_specific_dic = {
        "alpha_syscall_zero": [], # arch/alpha/kernel/entry.S
        "alpha_fork": [], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_osf_wait4": [
            "pid_t pid", "int __user *ustatus", "int options", "struct rusage32 __user *ur",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_brk": [
            "unsigned long brk",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxpid": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_mount": [
            "unsigned long typenr", "const char __user *path", "int flag", "void __user *data"
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxuid": [], # arch/alpha/kernel/osf_sys.c
        "sys_alpha_pipe": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_set_program_attributes": [
            "unsigned long text_start", "unsigned long text_len",
            "unsigned long bss_start", "unsigned long bss_len",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxgid": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sigprocmask": [
            "int how", "unsigned long newmask",
        ], # arch/alpha/kernel/signal.c
        "sys_getpagesize": [], # arch/alpha/kernel/osf_sys.c
        "alpha_vfork": [], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_osf_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getdtablesize": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_select": [
            "int, n, fd_set __user *inp", "fd_set __user *outp",
            "fd_set __user *exp", "struct timeval32 __user *tvp",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getpriority": [
            "int which", "int who",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_sigreturn": [], # arch/alpha/kernel/entry.S (sigreturn_like macro)
        "sys_osf_sigstack": [
            "struct sigstack __user *uss", "struct sigstack __user *uoss",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_gettimeofday": [
            "struct timeval32 __user *tv", "struct timezone __user *tz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getrusage": [
            "int who", "struct rusage32 __user *ru",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_settimeofday": [
            "struct timeval32 __user *tv", "struct timezone __user *tz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_utimes": [
            "const char __user *filename", "struct timeval32 __user *tvs",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sigaction": [
            "int, sig", "const struct osf_sigaction __user *act", "struct osf_sigaction __user *oact",
        ], # arch/alpha/kernel/signal.c
        "sys_osf_getdirentries": [
            "unsigned int fd", "struct osf_dirent __user *dirent",
            "unsigned int count", "long __user *basep",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_statfs": [
            "const char __user *pathname", "struct osf_statfs __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstatfs": [
            "unsigned long fd", "struct osf_statfs __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getdomainname": [
            "char __user *name", "int namelen",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_utsname": [
            "char __user *name",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_stat": [
            "char __user *name", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_lstat": [
            "char __user *name", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstat": [
            "int fd", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_statfs64": [
            "char __user *pathname", "struct osf_statfs64 __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstatfs64": [
            "unsigned long fd", "struct osf_statfs64 __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sysinfo": [
            "int command", "char __user *buf", "long count",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_proplist_syscall": [
            "enum pl_code code", "union pl_args __user *args",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_usleep_thread": [
            "struct timeval32 __user *sleep", "struct timeval32 __user *remain",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getsysinfo": [
            "unsigned long op", "void __user *buffer", "unsigned long nbytes",
            "int __user *start", "void __user *arg",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_setsysinfo": [
            "unsigned long op", "void __user *buffer", "unsigned long nbytes",
            "int __user *start", "void __user *arg",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_sethae": [
            "unsigned long val",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_old_adjtimex": [
            "struct timex32 __user *txc_p",
        ], # arch/alpha/kernel/osf_sys.c
        "alpha_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # arch/alpha/kernel/entry.S (fork_like macro)
        "alpha_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_rt_sigreturn": [], # arch/alpha/kernel/entry.S (sigreturn_like macro)
        "sys_rt_sigaction": [
            "int sig", "const struct sigaction __user *act", "struct sigaction __user *oact",
            "size_t sigsetsize", "void __user *restorer",
        ], # arch/alpha/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(alpha_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallHPPA32(Syscall):
    arch_specific_dic = {
        "sys_fork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pread64": [
            "unsigned int fd", "char __user *buf", "size_t count",
            "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pwrite64": [
            "unsigned int fd", "const char __user *buf", "size_t count",
            "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_vfork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_clone_wrapper": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/parisc/kernel/entry.S (fork_like macro, CONFIG_CLONE_BACKWARDS)
        "parisc_personality": [
            "unsigned long personality",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_rt_sigreturn_wrapper": [], # arch/parisc/kernel/entry.S
        "parisc_truncate64": [
            "const char __user * path", "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_ftruncate64": [
            "unsigned int fd", "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_readahead": [
            "int fd", "unsigned int high", "unsigned int low", "size_t count",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_fadvise64_64": [
            "int fd", "unsigned int high_off", "unsigned int low_off",
            "unsigned int high_len", "unsigned int low_len", "int advice",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_sync_file_range": [
            "int fd", "u32 hi_off", "u32 lo_off", "u32 hi_nbytes", "u32 lo_nbytes",
            "unsigned int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_fallocate": [
            "int fd", "int mode", "u32 offhi", "u32 offlo", "u32 lenhi", "u32 lenlo",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_timerfd_create": [
            "int clockid", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_signalfd4": [
            "int ufd", "sigset_t __user *user_mask", "size_t sizemask", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_eventfd2": [
            "unsigned int count", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pipe2": [
            "int __user *fildes", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_inotify_init1": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_userfaultfd": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_clone3_wrapper": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/parisc/kernel/entry.S (fork_like macro)
        "parisc_madvise": [
            "unsigned long start", "size_t len_in", "int behavior",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/parisc/kernel/cache.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(hppa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallHPPA64(Syscall):
    arch_specific_dic = {
        "sys_fork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_vfork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_clone_wrapper": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/parisc/kernel/entry.S (fork_like macro, CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn_wrapper": [], # arch/parisc/kernel/entry.S
        "parisc_timerfd_create": [
            "int clockid", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_signalfd4": [
            "int ufd", "sigset_t __user *user_mask", "size_t sizemask", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_eventfd2": [
            "unsigned int count", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pipe2": [
            "int __user *fildes", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_inotify_init1": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_userfaultfd": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_clone3_wrapper": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/parisc/kernel/entry.S (fork_like macro)
        "parisc_madvise": [
            "unsigned long start", "size_t len_in", "int behavior",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/parisc/kernel/cache.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c

    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(hppa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallOR1K(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/openrisc/kernel/entry.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp",
            "void __user *parent_tid", "void __user *child_tid", "int tls",
        ], # arch/openrisc/include/syscalls.h
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_or1k_atomic": [
            "unsigned long type", "unsigned long *v1", "unsigned long *v2",
        ], # arch/openrisc/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(or1k_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/openrisc/kernel/Makefile.syscalls
            if abi not in ["common", "32", "or1k", "time32", "stat64", "rlimit", "renameat"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallNIOS2(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/nios2/kernel/entry.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp",
            "int __user *parent_tidptr", "int __user *child_tidptr", "int tls_val",
        ], # arch/nios2/kernel/entry.S
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long len", "unsigned int op",
        ], # arch/nios2/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(nios2_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/nios2/kernel/Makefile.syscalls
            if abi not in ["common", "32", "nios2", "time32", "stat64", "renameat", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func in ["sys_clone3"]: # __ARCH_BROKEN_SYS_CLONE3
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMICROBLAZE(Syscall):
    arch_specific_dic = {
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/microblaze/kernel/sys_microblaze.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS3)
        "sys_rt_sigreturn_wrapper": [], # arch/microblaze/kernel/entry.S
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/microblaze/kernel/sys_microblaze.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(microblaze_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallXTENSA(Syscall):
    arch_specific_dic = {
        "xtensa_fadvise64_64": [
            "int fd", "int advice", "unsigned long long offset", "unsigned long long len",
        ], # arch/xtensa/kernel/syscall.c
        "xtensa_shmat": [
            "int shmid", "char __user *shmaddr", "int shmflg",
        ], # arch/xtensa/kernel/syscall.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "xtensa_rt_sigreturn": [], # arch/xtensa/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(xtensa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallCRIS(Syscall):
    arch_specific_dic = {
        "sys_sigreturn": [], # arch/cris/arch-v10/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS2)
        "sys_bdflush": [
            "int func", "long data",
        ], # include/linux/syscalls.h
        "sys_sysctl": [
            "struct __sysctl_args __user *args",
        ], # include/linux/syscalls.h
        "sys_rt_sigreturn": [], # arch/cris/arch-v10/kernel/signal.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/cris/kernel/sys_cris.c
        "sys_lookup_dcookie": [
            "u64 cookie64", "char __user *buf", "size_t, len",
        ], # fs/dcookies.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(cris_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "cris":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallLOONGARCH64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_rt_sigreturn": [], # arch/loongarch/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/loongarch/kernel/syscall.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(loongarch_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "loongarch":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARC(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/arc/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/arc/kernel/entry.S (sys_clone_wrapper, CONFIG_CLONE_BACKWARDS)
        "sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/arc/kernel/entry.S (sys_clone3_wrapper)
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # include/uapi/asm/unistd.h
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/arc/kernel/sys.c (sys_mmap_pgoff)
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_cacheflush": [
            "uint32_t start", "uint32_t sz", "uint32_t flags",
        ], # arch/arc/mm/cache.c
        "sys_arc_settls": [
            "void* user_tls_data_ptr",
        ], # arch/arc/kernel/process.c
        "sys_arc_gettls": [], # arch/arc/kernel/process.c
        "sys_sysfs": [
            "int option", "unsigned long arg1", "unsigned long arg2",
        ], # fs/filesystems.c
        "sys_arc_usr_cmpxchg": [
            "int __user *uaddr", "int expected", "int new",
        ], # arch/arc/kernel/process.c
    }

    @classmethod
    def make_syscall_list(cls, bit_str):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/arc/kernel/Makefile.syscalls
            if abi not in ["common", bit_str, "arc", "time32", "renameat", "stat64", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallCSKY(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_rt_sigreturn": [], # arch/csky/kernel/signal.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/csky/kernel/syscall.c
        "sys_fadvise64_64": [
            "int fd", "int advice", "loff_t offset", "loff_t len",
        ], # arch/csky/include/asm/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/csky/kernel/signal.c
        "sys_cacheflush": [
            "void __user *addr", "unsigned long len", "int op",
        ], # arch/csky/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(csky_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/csky/kernel/Makefile.syscalls
            if abi not in ["common", "32", "csky", "time32", "stat64", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list
#