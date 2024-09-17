#include "cipher.h"
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "1: enode \n 2: decode \n 3: break with length \n 4: break with brute force";
        return 1;
    }
    VigenereCipher cipher;
    string plain_text, cipher_text, key, key_length;

    switch (argv[1][0]) {
    case '1':
        getline(cin, plain_text);
        getline(cin, key);
        cout << cipher.encode(plain_text, key);
        break;
    case '2':
        getline(cin, cipher_text);
        getline(cin, key);
        cout << cipher.decode(cipher_text, key);
        break;
    case '3':
        getline(cin, cipher_text);
        getline(cin, key_length);
        int key_length_int;
        try {
            key_length_int = stoi(key_length);
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
            return 1;
        }
        cout << cipher.break_cipher(cipher_text, key_length_int);
        break;
    case '4':
        getline(cin, cipher_text);
        cout << cipher.break_cipher(cipher_text, 0);
        break;
    default:
        cout << "Not a Valid Option.\n";
        return 1;
    }
    return 0;



//     string output1 = cipher.encode("Hello world123!", "SECURITY");
//     cout << output1 << '\n';
//     string output2 = cipher.encode("hell-o wor ld!", "SECURITY");
//     cout << output2 << '\n';
//     output1 = cipher.decode(output1, "SECURITY");
//     cout << output1 << '\n';
//     output2 = cipher.decode(output2, "SECURITY");
//     cout << output2 << '\n';
//     cipher.encode("Hello world 123! Hello world 123!", "SECURITY");
//     cipher.encode("Hello !!", "SECURITY");

//     const string test = "Abstract—We evaluate two decades of proposals to replace \
// text passwords for general - purpose user authentication on the \
// web using a broad set of twenty - five usability, deployability \
// and security benefits that an ideal scheme might provide. \
// The scope of proposals we survey is also extensive, including \
// password management software, federated login protocols, \
// graphical password schemes, cognitive authentication schemes, \
// one - time passwords, hardware tokens, phone - aided schemes \
// and biometrics.Our comprehensive approach leads to key \
// insights about the difficulty of replacing passwords.Not only \
// does no known scheme come close to providing all desired \
// benefits: none even retains the full set of benefits that legacy \
// passwords already provide.In particular, there is a wide range \
// from schemes offering minor security benefits beyond legacy \
// passwords, to those offering significant security benefits in \
// return for being more costly to deploy or more difficult to use. \
// We conclude that many academic proposals have failed to gain \
// traction because researchers rarely consider a sufficiently wide \
// range of real - world constraints.Beyond our analysis of current \
// schemes, our framework provides an evaluation methodology \
// and benchmark for future web authentication proposals.";

//     const string test = "Once upon a time there was a bunny rabbit named Smiley. Smiley had big teeth, long ears and a little cotton-ball tail. The reason she was named Smiley is because she loved to smile. \
// Every day, Smiley would go hopping through the fields, eating clover. She was very quiet, but if her motions made a sound, they would sound something like: “hippety-hoppety, hippety-hoppety, hippety-hoppety,” and so on, all the day long. This made Smiley smile, to think about how her motions might sound if they did in fact make a sound. \
// One day, Smiley found a clover field she had never seen before. Something seemed different about this field. Smiley entered the field slowly, cautiously, sniffing around here and there, hither and yon, near and far, back and forth, side to side, etc. She wondered if the field was magic or enchanted or something like that. But no, it was just an ordinary field. \
// However, this got Smiley to thinking. Maybe there was a magic or otherwise enchanted field somewhere. There must be. She talked to her bunny rabbit friends (actually, wiggled her nose at them, since bunny rabbits can’t talk), and they all agreed that there must be a magic or otherwise enchanted field. \
// Smiley was determined to find it. So she set off early the next morning, wearing only the aforementioned smile, plus her bunny hair, teeth, tail, ears and whatnot, and tried to find the magic or otherwise enchanted field. \
// Instead of hopping along the so-called bunny trail, Smiley hopped along any trails she happened to find, including but not limited to deer trails, goat trails, sheep trails, snail trails, walrus trails, people trails, hippopotamus trails, cow trails, pig trails, dog trails, elk trails, llama trails, alpaca trails, did I mention goat trails already, kangaroo trails, and so on. But Smiley didn’t find any magic or otherwise enchanted field. She was starting to wonder if there really was a magic or otherwise enchanted field, or if this was just a story she had read once upon a time. She was getting tired of this quest. “It’s hopeless,” Smiley thought. \
// She decided she would take one more trail, and if it didn’t lead to the magic or otherwise enchanted field, she would give up. That would be so embarrassing, to admit to her friends that her quest had been for nothing. Smiley sure hoped this last trail would lead to the magic or otherwise enchanted field. \
// Smiley hopped down the next trail. She could tell it was a sheep trail, because there was a big sign, written in a language that only sheep could understand, saying “Sheep Trail.” Smiley briefly wondered how she could read the sign if in fact it was written in a language that only sheep could understand, but she wasn’t the kind of rabbit who wastes time pondering imponderables. For example, she had never spent much time calculating how many angels could hop on the head of a pin, or the median amount of wood the average wood chuck would chuck, etc. \
// Anyhoo, Smiley hopped down the sheep trail, until finally she came to a big white fence. She didn’t see any sheep, but she could tell they had been there, because there were fluffy white clumps of wool here and there on top of the fence. The wool smelled just like sleep. Hoppy, or whatever her name was, laid down for a minute, because she was tired from a long day of hopping down the non-bunny trails. She closed her eyes and imagined what it would be like to watch all those sheep, jumping over the fence. She could see them in her mind’s eye. She started counting them: one, two, three, one, two, three. Hoppy could only count to three, so she kept having to start over: one two three, one, two, three. It was easier that way, Hoppy rationalized, not having so many numbers. \
// Hoppy yawned. She wondered if she would ever find the enchanted waterfall. It didn’t matter. Look at all the soft and fluffy sheep. It made Hoppy wonder why wool is so itchy. But Hoppy couldn’t quite go back to sleep. So she continued watching and counting: one, two, three, one, two, three. \
// Then she climbed up on a sheep’s back and hopped right over the fence into Sleepyland. Everything was nice and slow in Sleepyland, and no one expected you to be able to count over three. Hoppy liked it very much. She thought to herself, “Maybe this is the magic kingdom or lantern I was looking for.” Hoppy checked her pockets and counted her change: one, two, three, one, two, three... Everything seemed to be in order. \
// “ Perhaps I’ll just take a little nap,” Hoppy said. All the sheep agreed. They curled up all around her and everything was warm and fluffy, like cotton candy if it was fluffy instead of sticky. Fluffy was so contented now. Life was good, at least at times like this, and if this wasn’t the Splendid Goulash she had been seeking, she could always look for it again tomorrow. \
// Ever since that day, Fluffy went all hippety-hoppety, down bunny and non-bunny trails alike, secure in the knowledge that, wherever she went, there she was. This made Fluffy smile a big, toothy grin. And ever since that day, she went by the name Smiley, and sometimes Flopsy.";


    // string key = "A";
    // string encode1 = cipher.encode(test, key);
    // string decode1 = cipher.break_cipher(encode1);
    // cout << decode1;
}