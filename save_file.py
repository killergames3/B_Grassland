import sys
import json

def save_file(file_path, content):
    try:
        # Convertir el contenido recibido desde Node.js en un diccionario Python
        data = json.loads(content)
        
        # Guardar el contenido en el archivo especificado
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"Archivo '{file_path}' guardado correctamente.")
    except Exception as e:
        print(f"Error al guardar el archivo: {e}")

if __name__ == "__main__":
    # Obtener los parámetros desde la línea de comandos
    file_path = sys.argv[1]  # La ruta del archivo
    content = sys.argv[2]     # El contenido (en formato JSON como cadena)

    # Llamar a la función para guardar el archivo
    save_file(file_path, content)
