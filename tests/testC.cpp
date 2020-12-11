#include <iostream>

template <typename Type> class Node {
private:
	Type value;
	Node *next;
public:
	Node(int val) : value(val) {}
	Node(int val, Node *next) : value(val), next(next) {}

	~Node() {
		if (next)
			next->~Node();
	}

	Type getValue() {
		return value;
	}

	void setValue(Type val) {
		value = val;
	}

	void push(Node *p) {
		next = p;
	}
};

int main() {
	Node<int> *root = new Node<int>(0);

	for (int i = 0; i < 5; i++) {
		int val;
		std::cin >> val;
		root->push(new Node<int>(val));
	}

	delete root;
}
