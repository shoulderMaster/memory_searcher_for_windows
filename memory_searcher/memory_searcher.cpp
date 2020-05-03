#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <set>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <string>
#include <mutex>
#include <thread>
//#include <QApplication>
using namespace std;




class MemoryMap {
public :
    vector<void*> base_addr_set;
    unordered_map<void*, int> memory_map;

    MemoryMap() {
        
    }

    MemoryMap(HANDLE h_process) {
        long long int prev_addr = 0;
        long long int cur_addr = 0;
        long long int max_addr = 0x7fffffff;
        int size = 0;
        MEMORY_BASIC_INFORMATION mbi;
        for (cur_addr = 0; cur_addr < max_addr; cur_addr += mbi.RegionSize) {
            VirtualQueryEx(h_process, (void*)cur_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
            if ((mbi.State & MEM_COMMIT) && (mbi.AllocationProtect & PAGE_READWRITE) && !(mbi.AllocationProtect & PAGE_GUARD)) {
                size += mbi.RegionSize;
                base_addr_set.push_back(mbi.BaseAddress);
                memory_map[mbi.BaseAddress] = (int)(mbi.RegionSize);
            }
        }
        printf("total commited pages size : %.2f MB\n", (float)size/1000000);
    }

    void* get_base_address(void* addr) {
        return *lower_bound(base_addr_set.rbegin(), base_addr_set.rend(), addr, [](void* a, void* b) {return a > b; });
    }

    int get_region_size(void* addr) {
        return memory_map[addr]; 
    }
};

class MemoryDump {
public :
    unordered_map<void*, void*> dump;
    vector<void*> base_addr_set;
    function<void(void*, void*, int)> memory_read_func;
    MemoryDump() {


    }

    MemoryDump(MemoryMap &p_memory_map, function<void(void*, void*, int)> p_memory_read_func) {
        this->MemoryDump::MemoryDump(p_memory_map.base_addr_set, p_memory_map, p_memory_read_func);
    }

    MemoryDump(vector<void*> &p_base_addr_set, MemoryMap &p_memory_map, function<void(void*, void*, int)> p_memory_read_func) {
        base_addr_set = p_base_addr_set;
        memory_read_func = p_memory_read_func;
        init_dump_map(p_memory_map);
    }

    ~MemoryDump() {
        for (auto entry : dump) {
            free(entry.second); // free allocated address
        }
    }

    void init_dump_map(MemoryMap &p_memory_map) {
        for (auto base_addr : base_addr_set) {
            int size = p_memory_map.get_region_size(base_addr);
            dump[base_addr] = malloc(size);
            memset(dump[base_addr], 0, size);
        }
    }

    void fully_dump(MemoryMap &p_memory_map) {
        for (auto base_addr : base_addr_set) {
            memory_refresh(base_addr, p_memory_map);
        }
    }

    void memory_refresh(void* base_addr, MemoryMap& p_memory_map) {
        int size = p_memory_map.get_region_size(base_addr);
        memory_read_func(base_addr, dump[base_addr], size);
    }


};

class Semaphore {

private:
    int cnt;
    mutex oper_lock;
    condition_variable cv;

public :

    Semaphore(int max_cnt) {
        cnt = max_cnt;
    }

    void up() { // post
        unique_lock<mutex> lck(oper_lock);
        //critical section begin
        cnt++;
        cv.notify_one();
        //critical section end
        
    }

    void down() { // wait
        unique_lock<mutex> lck(oper_lock);
        //critical section begin
        while (cnt == 0) {
            cv.wait(lck);
        }
        cnt--;
        //critical section end
    }

    int get_cnt() {
        return cnt;
    }


};

class Hack {

public:
    DWORD pid;
    HANDLE h_process;
    wstring process_name;
    MemoryMap memory_map;
    MemoryDump * memory_dump;
    MemoryDump * _next_dump;
    map<void*, vector<int>> var_info_db;
    function<void(void*, void*, int)> memory_read_func;

    Hack(wstring p_name) {
        pid = get_process_id(p_name);
        h_process = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
        init_memory_map();
        memory_read_func = [=](void* base_addr, void* buffer, int region_size) {
            ReadProcessMemory(h_process, base_addr, buffer, region_size, NULL);
        };
        memory_dump = new MemoryDump(memory_map, memory_read_func);
        _next_dump = new MemoryDump(memory_map, memory_read_func);
        /* memory_read_func = [this](void* base_addr, void* buffer, int region_size) {
            ReadProcessMemory(this->h_process, base_addr, buffer, region_size, NULL);
        }; */
        
    }

    ~Hack() {
        CloseHandle(h_process);
    }

    DWORD get_process_id(wstring process_name)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot)
        {
            PROCESSENTRY32 ProcessEntry32;
            BOOL bProcessFound;
            ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
            bProcessFound = Process32First(hSnapshot, &ProcessEntry32);
            while (bProcessFound)
            {
                wstring cur_ps_nm(ProcessEntry32.szExeFile);
                if (cur_ps_nm.find(process_name) != wstring::npos) {
                    wcout << ProcessEntry32.szExeFile << " " << ProcessEntry32.th32ProcessID << endl;
                    process_name = cur_ps_nm;
                    CloseHandle(hSnapshot);
                    return ProcessEntry32.th32ProcessID;
                }
                bProcessFound = Process32Next(hSnapshot, &ProcessEntry32);
            }
            CloseHandle(hSnapshot);
        }
        return -1;
    }

    void init_memory_map() {
        memory_map = MemoryMap(h_process);
    }

    void memory_read (void * base_addr, void * buffer, int region_size) {
        if (!ReadProcessMemory(h_process, base_addr, buffer, region_size, NULL))
            printf("memory read error\n");
    }
    
    void first_scan() {
        memory_dump->fully_dump(memory_map);
    }

    template <typename T>
    void _swap(T& a, T& b) {
        T tmp;
        tmp = a;
        a = b;
        b = tmp;
    }

    template <typename T>
    void next_scan(function<bool(T,T)> cmp) {
        map<void*, vector<int>> var_db;
        
        int var_size = sizeof(T);
        if (var_info_db.empty()) {
            _next_dump->fully_dump(memory_map);
            int total_len = memory_map.base_addr_set.size();
            for (int idx = 0; idx < total_len; idx++) {
                void* base_addr = memory_map.base_addr_set[idx];
                int size = memory_map.get_region_size(base_addr);
                for (int offset = 0; offset + var_size < size; offset++) {
                    T* origin_val_ptr = (T*)((char*)memory_dump->dump[base_addr] + offset);
                    T* next_val_ptr = (T*)((char*)_next_dump->dump[base_addr] + offset);
                    if (cmp(*origin_val_ptr, *next_val_ptr)) {
                        var_db[base_addr].push_back(offset);
                    }
                }
            }
            

        } else {
            for (auto entry : var_info_db) {
                void* base_addr = entry.first;
                _next_dump->memory_refresh(base_addr, memory_map);
                for (auto offset : entry.second) {
                    T* origin_val_ptr = (T*)((char*)memory_dump->dump[base_addr] + offset);
                    T* next_val_ptr = (T*)((char*)_next_dump->dump[base_addr] + offset);
                    if (cmp(*origin_val_ptr, *next_val_ptr)) {
                        var_db[base_addr].push_back(offset);
                    }   
                }
            }
        }
        var_info_db = var_db;
        swap<MemoryDump*>(memory_dump, _next_dump);
    }

    template <typename T>
    void next_scan_with_multi_threading(function<bool(T, T)> cmp) {
        map<void*, vector<int>> var_db;
        Semaphore sema(8);

        int var_size = sizeof(T);
        if (var_info_db.empty()) {
            _next_dump->fully_dump(memory_map);
            int total_len = memory_map.base_addr_set.size();
            for (auto base_addr : memory_map.base_addr_set) {
                var_db[base_addr] = vector<int>();
            }
            vector<pair<function<void()>, int>> jobs = make_second_scan_jobs(var_db, cmp);
            vector<thread> threads;
            for (auto& job : jobs) {
                auto func = [=, &sema]() {
                    sema.down();
                    job.first();
                    sema.up();
                };
                threads.push_back(thread (func));    
            }
            for (auto& t : threads) {
                t.join();
            }
        }
        else {
            for (auto entry : var_info_db) {
                void* base_addr = entry.first;
                _next_dump->memory_refresh(base_addr, memory_map);
                for (auto offset : entry.second) {
                    T* origin_val_ptr = (T*)((char*)memory_dump->dump[base_addr] + offset);
                    T* next_val_ptr = (T*)((char*)_next_dump->dump[base_addr] + offset);
                    if (cmp(*origin_val_ptr, *next_val_ptr)) {
                        var_db[base_addr].push_back(offset);
                    }
                }
            }
        }
        var_info_db = var_db;
        swap<MemoryDump*>(memory_dump, _next_dump);
    }

    template <typename T>
    pair<function<void()>, int> make_scan_job(void* base_addr, void* origin_buffer, void* updated_buffer, function<bool(T, T)> cmp, map<void*, vector<int>> &var_db,int var_size, int size) {
        return pair<function<void()>, int> {[=, &var_db]() {
            for (int offset = 0; offset + var_size < size; offset++) {
                T* origin_val_ptr = (T*)((char*)origin_buffer + offset);
                T* next_val_ptr = (T*)((char*)updated_buffer + offset);
                if (cmp(*origin_val_ptr, *next_val_ptr)) {
                    var_db[base_addr].push_back(offset);
                }
            }
        }, size};

    }

    template <typename T>
    vector<pair<function<void()>, int>> make_second_scan_jobs(map<void*, vector<int>> &var_db, function<bool(T, T)> cmp) {
        vector<pair<function<void()>, int>> jobs;

        int var_size = sizeof(T);
        if (var_info_db.empty()) {
            _next_dump->fully_dump(memory_map);
            int total_len = memory_map.base_addr_set.size();
            for (int idx = 0; idx < total_len; idx++) {
                void* base_addr = memory_map.base_addr_set[idx];
                int size = memory_map.get_region_size(base_addr);
                auto job = make_scan_job<T>(base_addr, memory_dump->dump[base_addr], _next_dump->dump[base_addr], cmp, var_db, var_size, size);
                jobs.push_back(job);
            }
        }
        return jobs;
    }

    int get_scaned_var_cnt() {
        int cnt = 0;
        for (auto entry : var_info_db)
            cnt += entry.second.size();
        return cnt;
    }

    template <typename T>
    void print_scaned_variables_info() {
        int var_size = sizeof(T);
        int var_cnt = get_scaned_var_cnt();
        if (var_cnt < 1000) {
            for (auto entry : var_info_db) {
                void* base_addr = entry.first;
                for (auto offset : entry.second) {
                    void* addr = (char*)base_addr + offset;
                    printf("0x%08x -> ", addr);
                    cout << *(T*)((char*)(memory_dump->dump[base_addr]) + offset) << endl;
                }
            }
        }
    }

};









int main()
{
    Hack proc(L"gamer.exe");
    proc.first_scan();
    printf("initial scan complete.\n");
    string cmd_str;
    while (true) {
        getline(cin, cmd_str);
        if (cmd_str.find("inc") != string::npos) {
            proc.next_scan<char>([](char a, char b) {return a < b; });
        } else if (cmd_str.find("dec") != string::npos) {
            proc.next_scan<char>([](char a, char b) {return a > b; });
        } else if (cmd_str.find("equal") != string::npos) {
            proc.next_scan<char>([](char a, char b) {return a == b; });
        } else if (cmd_str.find("match") != string::npos) {
            char target = atoi(cmd_str.substr(cmd_str.find(" ")).c_str());
            proc.next_scan_with_multi_threading<char>([=](char a, char b) {return b == target; });
        } else if (cmd_str.find("refresh") != string::npos) {
            proc.next_scan<char>([](char a, char b) {return true; });
        } else if (cmd_str.find("fuck") != string::npos) {
            break;
        }
        proc.print_scaned_variables_info<char>();
        printf("total %d variables have been scaned\n", proc.get_scaned_var_cnt());
    }
}
