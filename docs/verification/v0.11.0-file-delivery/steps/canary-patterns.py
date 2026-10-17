# Writes the V16 canary patterns (one per line) to argv[1]: every marker, the base64 of
# each full value (as a Secret's data holds it), and base64 forms of the marker needles
# at all three byte offsets. Run with `python3 -I`. Test markers only.
import base64,sys
pem="-----BEGIN RSA PRIVATE KEY-----\nTESTMARKER136LINE1\nTESTMARKER136LINE2\n-----END RSA PRIVATE KEY-----\n"
vals=["test-marker-db-url\n",pem,"test-marker-webhook","test-marker-jev","test-marker-blob-id","test-marker-blob-secret","test-marker-guide","https://otel.example.test","x-test-marker=136","test-marker-owner-url\n","test-marker-app-password","test-marker-log-level"]
needles=["test-marker","TESTMARKER136","otel.example.test"]
pats=set(v.strip() for v in vals if "\n" not in v.strip())|set(needles)
for v in vals: pats.add(base64.b64encode(v.encode()).decode().rstrip("="))
for n in needles:
    for off in range(3):
        b=base64.b64encode(b"x"*off+n.encode()).decode()
        # drop chars influenced by the padding prefix and the tail
        s=b[(off*4+2)//3+ (1 if off else 0):]
        s=s[:len(s)-4]
        if len(s)>=8: pats.add(s)
open(sys.argv[1],"w").write("\n".join(sorted(pats))+"\n")
print(len(pats),"patterns")
