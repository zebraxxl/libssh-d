module libssh.threading;

import core.sync.mutex;
import core.thread;
import std.algorithm.mutation;

import libssh.c_bindings.libssh;
import libssh.c_bindings.callbacks;
import libssh.utils;

version (LibSSHWithPThreads) {
    void initWithPThreads() {
        ssh_threads_set_callbacks(ssh_threads_get_pthread());
        ssh_init();
    }
}

struct ThreadsCallbacks {
    string type;
    bool function(ref void* lock) mutexInit;
    bool function(ref void* lock) mutexDestroy;
    bool function(ref void* lock) mutexLock;
    bool function(ref void* lock) mutexUnlock;
    uint function() getThreadId;
}

void initWithDLang() {
    ssh_threads_set_callbacks(&dlangThreadsCallbacks);
    ssh_init();
}

void initWithCustom(ThreadsCallbacks cb) {
    _customCallbacks = cb;
    libsshCustomThreadsStruct.type = toStrZ(cb.type);
    ssh_threads_set_callbacks(&libsshCustomThreadsStruct);
    ssh_init();
}

private {
    __gshared Mutex _internalMutex;
    __gshared Mutex[] _mutexes = [];     // To prevent GC collect mutexes sended to libssh

    extern(C) int dlangThreadsMutexInit(void** lock) {
        auto result = new Mutex();

        synchronized (_internalMutex) {
            _mutexes ~= result;
        }

        *lock = cast(void*) result;
        return 0;
    }

    extern(C) int dlangThreadsMutexDestroy(void** lock) {
        auto mutex = cast(Mutex) (*lock);

        synchronized (_internalMutex) {
            _mutexes = remove!(a => a == mutex)(_mutexes);
        }

        delete mutex;
        *lock = null;

        return 0;
    }

    extern(C) int dlangThreadsMutexLock(void** lock) {
        auto mutex = cast(Mutex) (*lock);

        mutex.lock();

        return 0;
    }

    extern(C) int dlangThreadsMutexUnlock(void** lock) {
        auto mutex = cast(Mutex) (*lock);

        mutex.unlock();

        return 0;
    }

    extern(C) uint dlangThreadsThreadId() {
        auto id = Thread.getThis().id;

        // Why? Why not =) I have not better idea to cast thread id to uint from ulong.
        // As for me - this variant is better than just remove hight part
        return cast(uint) (((cast(ulong)(id) & 0xffffffff00000000L) >> 32) ^ (cast(uint)(id) & 0xffffffff));
    }

    __gshared ssh_threads_callbacks_struct dlangThreadsCallbacks = {
        type:"dlang" ~ 0,
        mutex_init: &dlangThreadsMutexInit,
        mutex_destroy: &dlangThreadsMutexDestroy,
        mutex_lock: &dlangThreadsMutexLock,
        mutex_unlock: &dlangThreadsMutexUnlock,
        thread_id: &dlangThreadsThreadId,
    };

    shared static this() {
        _internalMutex = new Mutex();
    }


    __gshared ThreadsCallbacks _customCallbacks;

    extern(C) int customThreadsMutexInit(void** lock) {
        return _customCallbacks.mutexInit(*lock) ? 0 : -1;
    }
    
    extern(C) int customThreadsMutexDestroy(void** lock) {
        return _customCallbacks.mutexDestroy(*lock) ? 0 : -1;
    }
    
    extern(C) int customThreadsMutexLock(void** lock) {
        return _customCallbacks.mutexLock(*lock) ? 0 : -1;
    }
    
    extern(C) int customThreadsMutexUnlock(void** lock) {
        return _customCallbacks.mutexUnlock(*lock) ? 0 : -1;
    }
    
    extern(C) uint customThreadsGetThreadId() {
        return _customCallbacks.getThreadId();
    }

    __gshared ssh_threads_callbacks_struct libsshCustomThreadsStruct = {
            type: null,
            mutex_init: &customThreadsMutexInit,
            mutex_destroy: &customThreadsMutexDestroy,
            mutex_lock: &customThreadsMutexLock,
            mutex_unlock: &customThreadsMutexUnlock,
            thread_id: &customThreadsGetThreadId,
    };
}
