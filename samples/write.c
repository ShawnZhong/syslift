#include <unistd.h>

int main(void) {
  const char message[] = "hello, world!\n";
  if (write(STDOUT_FILENO, message, sizeof(message) - 1) < 0) {
    return 1;
  }
  return 0;
}
