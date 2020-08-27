branchIdentifiers = [
    'jo',
    'jno',
    'js',
    'jns',
    'je',
    'jz',
    'jne',
    'jnz',
    'jb',
    'jnae',
    'jc',
    'jnb',
    'jae',
    'jnc',
    'jbe',
    'jna',
    'ja',
    'jnbe',
    'jl',
    'jnge',
    'jge',
    'jnl',
    'jle',
    'jng',
    'jg',
    'jnle',
    'jp',
    'jpe',
    'jnp',
    'jpo',
    'jcxz',
    'jecxz'
]

callIdentifiers = ["callq", "jmpq"]
unconditionalJumpIdentifiers = "jmp"
returnIdentifier = "retq"
entryPoint = 'main'

UJUMP = type("UnconditionalJUMP", (object, ), {})
URETURN = type("UnconditionalRETURN", (object, ), {})

pieConfigOffset = 0x400000
