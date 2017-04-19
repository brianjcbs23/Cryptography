ciphertext = gets
ciphertext.strip!
plaintext = ""
(0..25).each do |n|
    ciphertext.each_char do |c|
        plaintext = plaintext + ((c.ord + n) % 25 + 97).chr
    end
    puts plaintext
    gets
    plaintext = ""
end
