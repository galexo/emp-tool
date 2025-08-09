#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-tool/utils/hash.h"

using namespace std;
using namespace emp;

class AbandonIO : public IOChannel<AbandonIO> {
public:
    void send_data_internal(const void*, int) {}
    void recv_data_internal(void*, int) {}
};

int port, party;

template <typename T>
void test(T* netio) {
    // === Inputs/outputs for the Bristol circuit ===
	block* key_blocks = new block[256];
	block* pt_blocks  = new block[128];
	block* out_blocks = new block[128];   // 128-bit ciphertext output

	PRG prg;
	prg.random_block(key_blocks, 256);
	prg.random_block(pt_blocks, 128);

	// Load the Bristol Fashion circuit
	string file = "./emp-tool/circuits/files/bristol_fashion/aes_256.txt";
	BristolFashion cf(file.c_str());
	// Build a single input array in bundle order: [256-bit bundle][128-bit bundle]
	int nin = 256 + 128;
	block* in_all = new block[nin];
	memcpy(in_all,          key_blocks, 256 * sizeof(block)); // first bundle (256)
	memcpy(in_all + 256,    pt_blocks,  128 * sizeof(block)); // second bundle (128)

    if (party == BOB) {
        // Evaluator: just evaluate with the provided IO (no extra local metrics)
        HalfGateEva<T>::circ_exec = new HalfGateEva<T>(netio);
        for (int i = 0; i < 100; ++i) cf.compute(out_blocks, in_all);
        delete HalfGateEva<T>::circ_exec;
    } else {
        // =======================
        // 1) CPU-only garbling
        // =======================
        auto* aio = new AbandonIO();
        HalfGateGen<AbandonIO>::circ_exec = new HalfGateGen<AbandonIO>(aio);
        auto* gen_cpu = HalfGateGen<AbandonIO>::circ_exec;

        uint64_t and_before = gen_cpu->num_and();
        auto t0 = clock_start();
        for (int i = 0; i < 100; ++i) cf.compute(out_blocks, in_all);
        double ms_garble = time_from(t0);
        uint64_t and_after = gen_cpu->num_and();
        uint64_t and_used = and_after - and_before;

        cout << "[CPU-only] AND gates: " << and_used << "\n";
        cout << "[CPU-only] Garbling time: " << ms_garble << " ms\n";

		delete aio;
        delete HalfGateGen<AbandonIO>::circ_exec;
        

		// ======================================
		// 2) Bytes to transfer + hash the blob
		//    (batched like the example: 20×(clear + 5 computes))
		// ======================================
		auto* mio = new MemIO();
		HalfGateGen<MemIO>::circ_exec = new HalfGateGen<MemIO>(mio);

		// Garble+write throughput over 20 batches of 5 computes
		auto t1 = clock_start();
		size_t total_bytes = 0;
		double total_hash_ms = 0.0;

		for (int batch = 0; batch < 20; ++batch) {
			mio->clear();

			// run 5 computes into a fresh buffer
			for (int j = 0; j < 5; ++j)
				cf.compute(out_blocks, in_all);

			// measure bytes produced in this batch
			size_t batch_bytes = mio->size;                 // or mio->get_size() in some versions
			total_bytes += batch_bytes;

			// hash the batch buffer
			Hash h; char dig[Hash::DIGEST_SIZE];
			auto th = clock_start();
			h.put(mio->buffer, (int)batch_bytes);           // or mio->get_buf()
			h.digest(dig);
			total_hash_ms += time_from(th);
		}
		double ms_garble_write = time_from(t1);

		// Report
		cout << "[MemIO] Garble+write time (20×5): " << ms_garble_write << " ms\n";
		cout << "[MemIO] Total serialized bytes (20×5): " << total_bytes << " bytes\n";
		cout << "[MemIO] Avg bytes per compute: " << (total_bytes / (20*5)) << " bytes\n";
		cout << "[MemIO] Total hash time (20 batches): " << total_hash_ms << " ms\n";
		cout << "[MemIO] Avg hash time per batch: " << (total_hash_ms / 20.0) << " ms\n";

		// Tear down: executor first, then IO
		delete HalfGateGen<MemIO>::circ_exec;
		delete mio;

       

        // ======================================
        // 3) Actual socket bytes with NetIO T*
        // ======================================
        HalfGateGen<T>::circ_exec = new HalfGateGen<T>(netio);
        uint64_t before_ctr = 0;
        before_ctr = netio->counter;   // only available if compiled with -DCOUNT_IO

        auto t3 = clock_start();
        for (int i = 0; i < 100; ++i) cf.compute(out_blocks, in_all);
        double ms_net = time_from(t3);

        uint64_t bytes_net = netio->counter - before_ctr;
        cout << "[NetIO] Socket bytes: " << bytes_net << " bytes\n";
        cout << "[NetIO] Garbling+network time: " << ms_net << " ms\n";

        delete HalfGateGen<T>::circ_exec;

    }

    delete[] key_blocks;
    delete[] pt_blocks;
    delete[] in_all;
	delete[] out_blocks;
}

int main(int argc, char** argv) {
    parse_party_and_port(argv, &party, &port);

    cout << "Using NetIO\n";
    auto* netio = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    test<NetIO>(netio);
    delete netio;

    cout << "Using HighSpeedNetIO\n";
    auto* hsnetio = new HighSpeedNetIO(party == ALICE ? nullptr : "127.0.0.1", port, port+1);
    test<HighSpeedNetIO>(hsnetio);
    delete hsnetio;

    return 0;
}
