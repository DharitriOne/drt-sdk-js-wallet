import { assert } from "chai";
import { Randomness } from "./crypto";
import { ErrInvariantFailed } from "./errors";
import { Mnemonic } from "./mnemonic";
import { TestMessage } from "./testutils/message";
import { TestTransaction } from "./testutils/transaction";
import { DummyMnemonic, DummyMnemonicOf12Words, DummyPassword, loadTestKeystore, loadTestWallet, TestWallet } from "./testutils/wallets";
import { UserSecretKey } from "./userKeys";
import { UserSigner } from "./userSigner";
import { UserVerifier } from "./userVerifier";
import { UserWallet } from "./userWallet";

describe("test user wallets", () => {
    let alice: TestWallet, bob: TestWallet, carol: TestWallet;
    let password: string = DummyPassword;

    before(async function () {
        alice = await loadTestWallet("alice");
        bob = await loadTestWallet("bob");
        carol = await loadTestWallet("carol");
    });

    it("should generate mnemonic", () => {
        let mnemonic = Mnemonic.generate();
        let words = mnemonic.getWords();
        assert.lengthOf(words, 24);
    });

    it("should derive keys", async () => {
        let mnemonic = Mnemonic.fromString(DummyMnemonic);

        assert.equal(mnemonic.deriveKey(0).hex(), alice.secretKeyHex);
        assert.equal(mnemonic.deriveKey(1).hex(), bob.secretKeyHex);
        assert.equal(mnemonic.deriveKey(2).hex(), carol.secretKeyHex);
    });

    it("should derive keys (12 words)", async () => {
        const mnemonic = Mnemonic.fromString(DummyMnemonicOf12Words);

        assert.equal(mnemonic.deriveKey(0).generatePublicKey().toAddress().bech32(), "moa1l8g9dk3gz035gkjhwegsjkqzdu3augrwhcfxrnucnyyrpc2220pq9dw30d");
        assert.equal(mnemonic.deriveKey(1).generatePublicKey().toAddress().bech32(), "moa1fmhwg84rldg0xzngf53m0y607wvefvamh07n2mkypedx27lcqntsc6kqe3");
        assert.equal(mnemonic.deriveKey(2).generatePublicKey().toAddress().bech32(), "moa1tyuyemt4xz2yjvc7rxxp8kyfmk2n3h8gv3aavzd9ru4v2vhrkcksvnlphz");

        assert.equal(mnemonic.deriveKey(0).generatePublicKey().toAddress("test").bech32(), "test1l8g9dk3gz035gkjhwegsjkqzdu3augrwhcfxrnucnyyrpc2220pqc6tnnf");
        assert.equal(mnemonic.deriveKey(1).generatePublicKey().toAddress("xmoa").bech32(), "xmoa1fmhwg84rldg0xzngf53m0y607wvefvamh07n2mkypedx27lcqntsldmzw9");
        assert.equal(mnemonic.deriveKey(2).generatePublicKey().toAddress("ymoa").bech32(), "ymoa1tyuyemt4xz2yjvc7rxxp8kyfmk2n3h8gv3aavzd9ru4v2vhrkcks7l8q0y");
    });

    it("should create secret key", () => {
        const keyHex = alice.secretKeyHex;
        const fromBuffer = new UserSecretKey(Buffer.from(keyHex, "hex"));
        const fromArray = new UserSecretKey(Uint8Array.from(Buffer.from(keyHex, "hex")));
        const fromHex = UserSecretKey.fromString(keyHex);

        assert.equal(fromBuffer.hex(), keyHex);
        assert.equal(fromArray.hex(), keyHex);
        assert.equal(fromHex.hex(), keyHex);
    });

    it("should compute public key (and address)", () => {
        let secretKey: UserSecretKey;

        secretKey = new UserSecretKey(Buffer.from(alice.secretKeyHex, "hex"));
        assert.equal(secretKey.generatePublicKey().hex(), alice.address.hex());
        assert.deepEqual(secretKey.generatePublicKey().toAddress(), alice.address);

        secretKey = new UserSecretKey(Buffer.from(bob.secretKeyHex, "hex"));
        assert.equal(secretKey.generatePublicKey().hex(), bob.address.hex());
        assert.deepEqual(secretKey.generatePublicKey().toAddress(), bob.address);

        secretKey = new UserSecretKey(Buffer.from(carol.secretKeyHex, "hex"));
        assert.equal(secretKey.generatePublicKey().hex(), carol.address.hex());
        assert.deepEqual(secretKey.generatePublicKey().toAddress(), carol.address);
    });

    it("should throw error when invalid input", () => {
        assert.throw(() => new UserSecretKey(Buffer.alloc(42)), ErrInvariantFailed);
        assert.throw(() => UserSecretKey.fromString("foobar"), ErrInvariantFailed);
    });

    it("should handle PEM files", () => {
        assert.equal(UserSecretKey.fromPem(alice.pemFileText).hex(), alice.secretKeyHex);
        assert.equal(UserSecretKey.fromPem(bob.pemFileText).hex(), bob.secretKeyHex);
        assert.equal(UserSecretKey.fromPem(carol.pemFileText).hex(), carol.secretKeyHex);
    });

    it("should create and load keystore files (with secret keys)", function () {
        this.timeout(10000);

        let aliceSecretKey = UserSecretKey.fromString(alice.secretKeyHex);
        let bobSecretKey = UserSecretKey.fromString(bob.secretKeyHex);
        let carolSecretKey = UserSecretKey.fromString(carol.secretKeyHex);

        console.time("encrypt");
        let aliceKeyFile = UserWallet.fromSecretKey({ secretKey: aliceSecretKey, password: password });
        let bobKeyFile = UserWallet.fromSecretKey({ secretKey: bobSecretKey, password: password });
        let carolKeyFile = UserWallet.fromSecretKey({ secretKey: carolSecretKey, password: password });
        console.timeEnd("encrypt");

        assert.equal(aliceKeyFile.toJSON().bech32, alice.address.bech32());
        assert.equal(bobKeyFile.toJSON().bech32, bob.address.bech32());
        assert.equal(carolKeyFile.toJSON().bech32, carol.address.bech32());

        console.time("decrypt");
        assert.deepEqual(UserWallet.decryptSecretKey(aliceKeyFile.toJSON(), password), aliceSecretKey);
        assert.deepEqual(UserWallet.decryptSecretKey(bobKeyFile.toJSON(), password), bobSecretKey);
        assert.deepEqual(UserWallet.decryptSecretKey(carolKeyFile.toJSON(), password), carolSecretKey);
        console.timeEnd("decrypt");

        // With provided randomness, in order to reproduce our development wallets

        aliceKeyFile = UserWallet.fromSecretKey({
            secretKey: aliceSecretKey,
            password: password,
            randomness: new Randomness({
                id: alice.keyFileObject.id,
                iv: Buffer.from(alice.keyFileObject.crypto.cipherparams.iv, "hex"),
                salt: Buffer.from(alice.keyFileObject.crypto.kdfparams.salt, "hex")
            })
        });

        bobKeyFile = UserWallet.fromSecretKey({
            secretKey: bobSecretKey,
            password: password,
            randomness: new Randomness({
                id: bob.keyFileObject.id,
                iv: Buffer.from(bob.keyFileObject.crypto.cipherparams.iv, "hex"),
                salt: Buffer.from(bob.keyFileObject.crypto.kdfparams.salt, "hex")
            })
        });

        carolKeyFile = UserWallet.fromSecretKey({
            secretKey: carolSecretKey,
            password: password,
            randomness: new Randomness({
                id: carol.keyFileObject.id,
                iv: Buffer.from(carol.keyFileObject.crypto.cipherparams.iv, "hex"),
                salt: Buffer.from(carol.keyFileObject.crypto.kdfparams.salt, "hex")
            })
        });

        assert.deepEqual(aliceKeyFile.toJSON(), alice.keyFileObject);
        assert.deepEqual(bobKeyFile.toJSON(), bob.keyFileObject);
        assert.deepEqual(carolKeyFile.toJSON(), carol.keyFileObject);
    });

    it("should load keystore files (with secret keys, but without 'kind' field)", async function () {
        const keyFileObject = await loadTestKeystore("withoutKind.json");
        const secretKey = UserWallet.decryptSecretKey(keyFileObject, password);

        assert.equal(secretKey.generatePublicKey().toAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
    });

    it("should create and load keystore files (with mnemonics)", async function () {
        this.timeout(10000);

        const wallet = UserWallet.fromMnemonic({ mnemonic: DummyMnemonic, password: password });
        const json = wallet.toJSON();

        assert.equal(json.version, 4);
        assert.equal(json.kind, "mnemonic");
        assert.isUndefined(json.bech32);

        const mnemonic = UserWallet.decryptMnemonic(json, password);
        const mnemonicText = mnemonic.toString();

        assert.equal(mnemonicText, DummyMnemonic);
        assert.equal(mnemonic.deriveKey(0).generatePublicKey().toAddress().bech32(), alice.address.bech32());
        assert.equal(mnemonic.deriveKey(1).generatePublicKey().toAddress().bech32(), bob.address.bech32());
        assert.equal(mnemonic.deriveKey(2).generatePublicKey().toAddress().bech32(), carol.address.bech32());

        // With provided randomness, in order to reproduce our test wallets
        const expectedDummyWallet = await loadTestKeystore("withDummyMnemonic.json");
        const dummyWallet = UserWallet.fromMnemonic({
            mnemonic: DummyMnemonic,
            password: password,
            randomness: new Randomness({
                id: "5b448dbc-5c72-4d83-8038-938b1f8dff19",
                iv: Buffer.from("2da5620906634972d9a623bc249d63d4", "hex"),
                salt: Buffer.from("aa9e0ba6b188703071a582c10e5331f2756279feb0e2768f1ba0fd38ec77f035", "hex")
            })
        });

        assert.deepEqual(dummyWallet.toJSON(), expectedDummyWallet);
    });

    it("should loadSecretKey, but without 'kind' field", async function () {
        const keyFileObject = await loadTestKeystore("withoutKind.json");
        const secretKey = UserWallet.decrypt(keyFileObject, password);

        assert.equal(secretKey.generatePublicKey().toAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
    });

    it("should throw when calling loadSecretKey with unecessary address index", async function () {
        const keyFileObject = await loadTestKeystore("alice.json");

        assert.throws(() => UserWallet.decrypt(keyFileObject, password, 42), "addressIndex must not be provided when kind == 'secretKey'");
    });

    it("should loadSecretKey with mnemonic", async function () {
        const keyFileObject = await loadTestKeystore("withDummyMnemonic.json");

        assert.equal(UserWallet.decrypt(keyFileObject, password, 0).generatePublicKey().toAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
        assert.equal(UserWallet.decrypt(keyFileObject, password, 1).generatePublicKey().toAddress().bech32(), "moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk");
        assert.equal(UserWallet.decrypt(keyFileObject, password, 2).generatePublicKey().toAddress().bech32(), "moa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaqhr5l9h");
    });

    it("should sign transactions", async () => {
        let signer = new UserSigner(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf"));
        let verifier = new UserVerifier(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf").generatePublicKey());

        // With data field
        let transaction = new TestTransaction({
            nonce: 0,
            value: "0",
            receiver: "moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn",
            gasPrice: 1000000000,
            gasLimit: 50000,
            data: "foo",
            chainID: "1",
        });

        let serialized = transaction.serializeForSigning();
        let signature = await signer.sign(serialized);

        assert.deepEqual(await signer.sign(serialized), await signer.sign(Uint8Array.from(serialized)));
        assert.equal(serialized.toString(), `{"nonce":0,"value":"0","receiver":"moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn","sender":"","gasPrice":1000000000,"gasLimit":50000,"data":"Zm9v","chainID":"1","version":1}`);
        assert.equal(signature.toString("hex"), "4a6cc5dbf051b44c04c242e48c3f6ad43946c354d1f66c1ac1e3dd093da9d9bdb5663016cc8da56768afa3e41c4196ea8af6233759269971132f49d92b28c00f");
        assert.isTrue(verifier.verify(serialized, signature));
        
        // Without data field
        transaction = new TestTransaction({
            nonce: 8,
            value: "10000000000000000000",
            receiver: "moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn",
            gasPrice: 1000000000,
            gasLimit: 50000,
            chainID: "1"
        });

        serialized = transaction.serializeForSigning();
        signature = await signer.sign(serialized);

        assert.deepEqual(await signer.sign(serialized), await signer.sign(Uint8Array.from(serialized)));
        assert.equal(serialized.toString(), `{"nonce":8,"value":"10000000000000000000","receiver":"moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn","sender":"","gasPrice":1000000000,"gasLimit":50000,"chainID":"1","version":1}`);
        assert.equal(signature.toString("hex"), "bb4bdf1be8dea817dfddec85a41302b9f57f85756b8d8eb8f4dd203e4839be60b9bf351c94fdefb7958d9b443dbee01771cedc0518ea099cd3a9e9cb56280702");
    });

    it("guardian should sign transactions from PEM", async () => {
        // bob is the guardian
        let signer = new UserSigner(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf"));
        let verifier = new UserVerifier(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf").generatePublicKey());
        let guardianSigner = new UserSigner(UserSecretKey.fromPem(bob.pemFileText));

        // With data field
        let transaction = new TestTransaction({
            nonce: 0,
            value: "0",
            receiver: "moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn",
            sender: "moa1l453hd0gt5gzdp7czpuall8ggt2dcv5zwmfdf3sd3lguxseux2fskgws3j",
            gasPrice: 1000000000,
            gasLimit: 50000,
            data: "foo",
            chainID: "1",
            guardian: "moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk",
            options: 2,
            version: 2
        });

        let serialized = transaction.serializeForSigning();
        let signature = await signer.sign(serialized);
        let guardianSignature = await guardianSigner.sign(serialized);

        assert.equal(serialized.toString(), `{"nonce":0,"value":"0","receiver":"moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn","sender":"moa1l453hd0gt5gzdp7czpuall8ggt2dcv5zwmfdf3sd3lguxseux2fskgws3j","guardian":"moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk","gasPrice":1000000000,"gasLimit":50000,"data":"Zm9v","chainID":"1","options":2,"version":2}`);
        assert.equal(signature.toString("hex"), "1bc971d92519b064404582b79767d854f5077617d7f9e98abc0a191688c858d7b3c0564b0124142667d596d81dcee7ee10c643d3c1ee3043b02799b0044b6501");
        assert.equal(guardianSignature.toString("hex"), "5389cdc44aa47957d531ba2f4f223f3a152d3dfa13bc5ebc82f5ec7661a2c60edf6c4ebaac41c63005f9be13ddfbda77720b08c1bf3b8152f74c332bc27f5c02");
        assert.isTrue(verifier.verify(serialized, signature));

        // Without data field
        transaction = new TestTransaction({
            nonce: 8,
            value: "10000000000000000000",
            receiver: "moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn",
            sender: "moa1l453hd0gt5gzdp7czpuall8ggt2dcv5zwmfdf3sd3lguxseux2fskgws3j",
            gasPrice: 1000000000,
            gasLimit: 50000,
            chainID: "1",
            guardian: "moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk",
            options: 2,
            version: 2,
        });

        serialized = transaction.serializeForSigning();
        signature = await signer.sign(serialized);
        guardianSignature = await guardianSigner.sign(serialized);

        assert.equal(serialized.toString(), `{"nonce":8,"value":"10000000000000000000","receiver":"moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn","sender":"moa1l453hd0gt5gzdp7czpuall8ggt2dcv5zwmfdf3sd3lguxseux2fskgws3j","guardian":"moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk","gasPrice":1000000000,"gasLimit":50000,"chainID":"1","options":2,"version":2}`);
        assert.equal(signature.toString("hex"), "0d853d968bbd2da435af0917050e815beaad45a3709fda6dc29a115d926ca00a81ea3efe4dc9fa5fec2b06e57579dc2f5fe70e1e0b8f0d9220daf9ff7e4b6a09");
        assert.equal(guardianSignature.toString("hex"), "6f34e571449644da0edfe2bc1f32d7dc8a4947f210ab0ce00e47fbaa38e8c8bbd940b6b5bc705d66fd7381fa4cdaeb9c7e40f4843d79cf94b2d6a9b5dbb1d901");
        assert.isTrue(verifier.verify(serialized, signature));
    });

    it("should sign transactions using PEM files", async () => {
        const signer = UserSigner.fromPem(alice.pemFileText);

        const transaction = new TestTransaction({
            nonce: 0,
            value: "0",
            receiver: "moa1cux02zersde0l7hhklzhywcxk4u9n4py5tdxyx7vrvhnza2r4gmqc5g7gn",
            gasPrice: 1000000000,
            gasLimit: 50000,
            data: "foo",
            chainID: "1"
        });

        const serialized = transaction.serializeForSigning();
        const signature = await signer.sign(serialized);

        assert.deepEqual(await signer.sign(serialized), await signer.sign(Uint8Array.from(serialized)));
        assert.equal(signature.toString("hex"), "8f73a756e809372fc097b6c4eb28df8131e238c8103d72837942e1b3ec970dc92b04e4e624c4f1e6f37a7b63f723ecd912dee6a22b73d7d0bf53d4227b09c005");
    });

    it("signs a general message", async function () {
        let signer = new UserSigner(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf"));
        let verifier = new UserVerifier(UserSecretKey.fromString("1a927e2af5306a9bb2ea777f73e06ecc0ac9aaa72fb4ea3fecf659451394cccf").generatePublicKey());

        const message = new TestMessage({
            foo: "hello",
            bar: "world"
        });

        const data = message.serializeForSigning();
        const signature = await signer.sign(data);

        assert.deepEqual(await signer.sign(data), await signer.sign(Uint8Array.from(data)));
        assert.isTrue(verifier.verify(data, signature));
        assert.isTrue(verifier.verify(Uint8Array.from(data), Uint8Array.from(signature)));
        assert.isFalse(verifier.verify(Buffer.from("hello"), signature));
        assert.isFalse(verifier.verify(new TextEncoder().encode("hello"), signature));
    });

    it("should create UserSigner from wallet", async function () {
        const keyFileObjectWithoutKind = await loadTestKeystore("withoutKind.json");
        const keyFileObjectWithMnemonic = await loadTestKeystore("withDummyMnemonic.json");
        const keyFileObjectWithSecretKey = await loadTestKeystore("withDummySecretKey.json");

        assert.equal(UserSigner.fromWallet(keyFileObjectWithoutKind, password).getAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password).getAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithSecretKey, password).getAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 0).getAddress().bech32(), "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 1).getAddress().bech32(), "moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 2).getAddress().bech32(), "moa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaqhr5l9h");

        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 0).getAddress("test").bech32(), "test1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ss5hqhtr");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 1).getAddress("xmoa").bech32(), "xmoa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruqgn3hez");
        assert.equal(UserSigner.fromWallet(keyFileObjectWithMnemonic, password, 2).getAddress("ymoa").bech32(), "ymoa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaq90v7a3");
    });

    it("should throw error when decrypting secret key with keystore-mnemonic file", async function () {
        const userWallet = UserWallet.fromMnemonic({
            mnemonic: DummyMnemonic,
            password: ``
        });
        const keystoreMnemonic = userWallet.toJSON();

        assert.throws(() => {
            UserWallet.decryptSecretKey(keystoreMnemonic, ``)
        }, `Expected keystore kind to be secretKey, but it was mnemonic.`);
    });
});
