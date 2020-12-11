#include <stdio.h>

int foo() {
	puts("buffer overflow?");
}

int main() {
	char bof[64];
	fgets(bof, 2 * sizeof bof, stdin);
}
