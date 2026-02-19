#include <unistd.h>

int main(void) {
  long a = getpid();
  long b = getuid();
  return (int)(a + b);
}
