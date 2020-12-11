#include <iostream>

int main() {
	/* How are sigsegvs handled? */
	int opt;
	std::cin >> opt;

	switch (opt) {
		case 0:
			return opt/opt;
		case 1:
			return *(&opt-0xffffffff);
		case 2:
			return ((int(*)()) &opt)();
		case 3:
			return 0;
		default:
			return (main - 1)();
	}
}
