import os
from docx import Document
import pdfplumber
from io import BytesIO

class FileHandler:
    @staticmethod
    def read_pdf(file):
        """Extract text from PDF using pdfplumber, preserve better layout"""
        text = ""
        # Jika file adalah BytesIO dari Flask upload
        if hasattr(file, 'read'):
            file.seek(0)  # Reset pointer ke awal file
        
        with pdfplumber.open(file) as pdf:
            for i, page in enumerate(pdf.pages):
                page_text = page.extract_text()
                if page_text:
                    text += f"--- Halaman {i+1} ---\n{page_text.strip()}\n\n"
        return text

    @staticmethod
    def read_docx(file):
        """Read content from DOCX file"""
        # Jika file adalah BytesIO dari Flask upload
        if hasattr(file, 'seek'):
            file.seek(0)  # Reset pointer ke awal file
            
        doc = Document(file)
        text = ""
        for para in doc.paragraphs:
            text += para.text + "\n"
        return text
        
    @staticmethod
    def get_file_extension(filename):
        """Get file extension in lowercase"""
        return os.path.splitext(filename)[1].lower()