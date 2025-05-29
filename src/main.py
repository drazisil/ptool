import ctypes
import struct

ctypes.CDLL("libc.so.6")  # Load the C standard library for ctypes
# Define a class to represent the PE file header
class PEFile():
    fields = [
        ("Signature", ctypes.c_char * 4),  # PE\0\0
        ("Machine", ctypes.c_uint16),      # Machine type
        ("NumberOfSections", ctypes.c_uint16),  # Number of sections
        ("TimeDateStamp", ctypes.c_uint32),  # Time and date stamp
        ("PointerToSymbolTable", ctypes.c_uint32),  # Pointer to symbol table
        ("NumberOfSymbols", ctypes.c_uint32),  # Number of symbols
        ("SizeOfOptionalHeader", ctypes.c_uint16),  # Size of optional header
        ("Characteristics", ctypes.c_uint16)  # Characteristics
    ]

    def __init__(self):
        self.size = struct.calcsize(self.format())  # Dynamically calculate size

    def format(self):
        return "4sHHLLHH"  # Format string for struct packing/unpacking
    def __sizeof__(self):
        return self.size
    def __repr__(self):
        return f"PEFile(size={self.size})"
    def __str__(self):
        return f"PEFile(size={self.size})"
    def __len__(self):
        return self.size
    
    def __iter__(self):
        for field in self.fields:
            yield field[0], field[1].__name__
    def __getattr__(self, name):
        for field in self.fields:
            if field[0] == name:
                return field[1]
        raise AttributeError(f"{name} not found in PEFile fields")
    def __setattr__(self, name, value):
        for field in self.fields:
            if field[0] == name:
                if isinstance(value, field[1]):
                    object.__setattr__(self, name, value)
                else:
                    raise TypeError(f"Expected {field[1].__name__} for {name}, got {type(value).__name__}")
                return
        object.__setattr__(self, name, value)
    

    def unpack(self, data):
        if len(data) != self.size:
            raise ValueError(f"Data size {len(data)} does not match expected size {self.size}")
        return struct.unpack(self.format(), data)
    
    def pack(self, *args):
        if len(args) != len(self.fields):
            raise ValueError(f"Expected {len(self.fields)} arguments, got {len(args)}")
        return struct.pack(self.format(), *args)
    
# Main function to demonstrate the PEFile class    
def main():
    file = "/home/drazisil/Downloads/MCity_d.exe"

    pe = PEFile()
    with open(file, "rb") as f:
        data = f.read(pe.size)
        unpacked_data = pe.unpack(data)
    
    print("Unpacked PE File Header:")
    for field, value in zip(pe.fields, unpacked_data):
        print(f"{field[0]}: {value} ({field[1].__name__})")



if __name__ == "__main__":
    main()
