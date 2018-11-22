find src/main/java -type f -print0 | xargs -0 sed -i 's|org.bouncycastle|org.spongycastle|g'
find src/main/java -type f -print0 | xargs -0 sed -i 's|.setProvider("BC")|.setProvider("SC")|g'

find src/test/java -type f -print0 | xargs -0 sed -i 's|org.bouncycastle|org.spongycastle|g'
find src/test/java -type f -print0 | xargs -0 sed -i 's|.setProvider("BC")|.setProvider("SC")|g'