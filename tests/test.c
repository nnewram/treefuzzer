#include <stdio.h>

int lmao(int* a) {
	if (*a > 100) {
		*a -= 1;
		return a+1;
	}
	return 69;
}

int lesad(int* a) {
	if (*a && (a != *a) && (*a == 32))
		return lmao(a);
	return 7;
}

int main() {
	int a;
	scanf("%d\n", &a);
	if (a > 105)
		return a;
	if (a > 69) {
		a = lmao(&a);
	}
	else {
		a = lesad(&a);
	}
	return a;
}
