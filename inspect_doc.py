"""Shows exactly what text VaultMind can read from a file. Run: python inspect_doc.py file.pdf"""
import sys
import rag

if len(sys.argv) < 2:
    raise SystemExit('Usage: python inspect_doc.py "path\\to\\file"')
path = sys.argv[1]
text = rag.extract_text(path, open(path, "rb").read())
print(f"{len(text)} characters, {len(rag.chunk_text(text))} passages\n" + "-" * 50)
print(text)
