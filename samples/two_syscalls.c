#include <unistd.h>

int main(void) { return (getpid() == ENOSYS) + (getuid() == ENOSYS); }
