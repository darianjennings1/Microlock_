def create_secure_contact(uname, fname, lname, email,public_key):
    with open(f"./contacts/{uname}.txt","w") as f:
        f.write(f"Name: {fname} {lname}\n\n")
        f.write(f"Email: {email}\n\n")
        f.write(f"Public Key: {public_key}")

def get_secure_contact(user):
    try:

        name = ""
        email = ""
        public_key = ""

        sc_file = f"./contacts/{user}.txt"
        with open(sc_file,"r") as f:
            lines = [line.rstrip() for line in f]
        
        for i,line in enumerate(lines):
            if line.startswith("Name:"):
                name = ' '.join(line.split(" ")[1:])
            elif line.startswith("Email:"):
                email = ' '.join(line.split(" ")[1:])
            elif line.startswith("Public Key:"):
                public_key = ' '.join(line.split(" ")[2:])
                public_key += '\n'
                for working_line in lines[i+1:]:
                    public_key+=working_line
                    public_key += '\n'
            else:
                pass
        
        return name, email, public_key
    except:
        return -1,-1,-1
