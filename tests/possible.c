#include <stdio.h>

int main() {
	int a;
	char b[16];
	fgets(b, 16, stdin);
	a = atoi(b);
	a = a > 0 ? a : -a;
	if (a > 13) {
		puts("reachable 1");
	}
	else if (a > 7) {
		puts("reachable 2");
	}
	else if (a > 0) {
		puts("reachable 3");
	}
	else {
		puts("unreachable");
	}
}
