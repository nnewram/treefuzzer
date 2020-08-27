int foo(int b) {
	if (b != 3) {
		return 123;
	}
	return 2;
}
int main() {
	int a = 4;
	if (a > 2) {
		return foo(a);
	}
	else {
		return 6;
	}
}
