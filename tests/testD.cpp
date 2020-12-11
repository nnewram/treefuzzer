#include <iostream>
/* simple crackme */

char correct[] = "why would i ever expose a key in this fascion?";

char encrypt(char a, char b) {
	return ((((a ^ b ^ 0x42) - 1) % 26)) + 'a';
}

bool verify(std::string key) {
	for (int i = 0; i < key.size(); i += 2) {
		if (encrypt(key[i], key[i + 1]) != correct[i >> 2])
			return false;
	}

	return true;
}

int main() {
	std::string key;
	std::cout << "Enter key: ";
	std::cin >> key;
	if (verify(key))
		std::cout << "The key is correct!" << std::endl;
	else
		std::cout << "The key is incorrect!" << std::endl;
}
