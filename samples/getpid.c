#include <unistd.h>

int main(void) { return getpid() == ENOSYS ? 0 : 1; }
