import requests
import os

def generate_whitelist_file(target_path='whitelist.txt'):
    # The official permanent URL for the latest Tranco list
    url = "https://tranco-list.eu/top-1m.csv.zip"
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(current_dir, target_path)
    
    print(f"Downloading top domains to {full_path}...")
    
    try:
        # Step 1: Request the full list (ZIP format)
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            import zipfile
            import io
            
            # Step 2: Extract the CSV from the ZIP in memory
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                csv_filename = z.namelist()[0]
                with z.open(csv_filename) as f:
                    content = f.read().decode('utf-8')
            
            # Step 3: Parse the first 10,000 domains
            lines = content.splitlines()
            # Tranco format is "Rank,Domain"
            domains = [line.split(',')[1] for line in lines[:10000] if ',' in line]
            
            with open(full_path, 'w') as out:
                for d in domains:
                    out.write(f"{d}\n")
            
            print(f"✅ Success! {len(domains)} domains saved to {target_path}")
        else:
            print(f"❌ Failed. Server returned Status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ An error occurred: {e}")
        print("Tip: If the download fails, manually create 'whitelist.txt' with common domains.")

if __name__ == "__main__":
    generate_whitelist_file()