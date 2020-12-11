#include <stdio.h>

int foo(int bar) {
	if (bar > 500) {
		return -5;
	}
	return 0;
}

int main() {
	int a;
	scanf("%d", &a);
	switch (a) {
		case 0 ... 100:
			puts("branch 1.");
			break;
		case 101 ... 1000:
			puts("branch 2.");
			break;
		case 1001 ... 5000:
			puts("branch 3.");
			break;
		default:
			puts("branch 4.");
	}

	return foo(a);
}
