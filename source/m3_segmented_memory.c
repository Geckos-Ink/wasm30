#include "m3_segmented_memory.h"
#include "esp_log.h"
#include "m3_pointers.h"
#include "wasm3.h"
#include <stdint.h>

#include "m3_debug.h"

#define WASM_SEGMENTED_MEM_LAZY_ALLOC true

DEBUG_TYPE WASM_DEBUG_GET_OFFSET_POINTER = WASM_DEBUG_ALL || (WASM_DEBUG && false);
DEBUG_TYPE WASM_DEBUG_M3_INIT_MEMORY = WASM_DEBUG_ALL || (WASM_DEBUG && false);

#define PRINT_PTR(ptr) ESP_LOGI("WASM3", "Pointer value: (unsigned: %u, signed: %d)", (uintptr_t)ptr, (intptr_t)ptr)
#define MIN(x, y) ((x) < (y) ? (x) : (y)) 

#if ENABLE_WDT
static mos check_wdt_trigger_every = 5;
static mos check_wdt_trigger_cycle = 0;

DEBUG_TYPE WASM_DEBUG_check_wdt_reset = false;
void check_wdt_reset(){
    if(check_wdt_trigger_cycle++ % check_wdt_trigger_every == 0){
        CALL_WATCHDOG

        if(WASM_DEBUG_check_wdt_reset) ESP_LOGD("WASM3", "m3_segmented_memory.c: CALL_WATCHDOG");
    }
}
#else 
void check_wdt_reset(){}
#endif

DEBUG_TYPE WASM_DEBUG_SEGMENTED_MEMORY_ALLOC = WASM_DEBUG_ALL || (WASM_DEBUG && false);

const bool DEBUG_WASM_INIT_MEMORY = false;
// Utility functions
static bool is_address_in_segment(MemorySegment* seg, void* ptr) {
    if (!seg || !seg->data || !ptr) return false;
    return (ptr >= seg->data && ptr < (char*)seg->data + seg->size);
}

static size_t get_segment_index(M3Memory* memory, void* ptr) {
    for (size_t i = 0; i < memory->num_segments; i++) {
        if (is_address_in_segment(memory->segments[i], ptr)) return i;
    }
    return (size_t)-1;
}

////////////////////////////////////////////////////////////////////////

IM3MemoryPoint m3_GetMemoryPoint(IM3Memory mem){
    IM3MemoryPoint res = m3_Def_AllocStruct(M3MemoryPoint);
    if(res != NULL){
        res->memory = mem;
        res->firm = 20190394;
    }
    return res;
}

IM3MemoryPoint ValidateMemoryPoint(void* ptr) {
    if (ptr == NULL) {
        return NULL;
    }

    if(!is_ptr_valid(ptr)){
        return NULL;
    }
    
    IM3MemoryPoint point = (IM3MemoryPoint)ptr;
    
    // Verifica la firma
    if (point->firm != M3PTR_FIRM) {
        return NULL;
    }
    
    return point;
}

////////////////////////////////////////////////////////////////

mos get_offset_pointer(IM3Memory memory, void* ptr) {
    check_wdt_reset();

    if (!memory || memory->firm != INIT_FIRM || !memory->segments || !ptr) {
        if(WASM_DEBUG_GET_OFFSET_POINTER) ESP_LOGW("WASM3", "get_offset_pointer: null memory or invalid ptr");
        return (mos)ptr;
    }

    // If ptr is already an offset or ERROR_POINTER, return it as is
    if(WASM_DEBUG_GET_OFFSET_POINTER) ESP_LOGW("WASM3", "get_offset_pointer: ptr= %d, memory->total_size= %d", (mos)ptr, memory->total_size);
    if (ptr == ERROR_POINTER || (mos)ptr < memory->total_size) {
        return (mos)ptr;
    }

    // Search through all segments to find which one contains this pointer
    for (size_t i = 0; i < memory->num_segments; i++) {
        MemorySegment* segment = memory->segments[i];
        if (!segment || !segment->data) continue;

        // Calculate if ptr falls within this segment's range
        void* segment_start = segment->data;
        void* segment_end = (uint8_t*)segment_start + segment->size;

        if (ptr >= segment_start && ptr < segment_end) {
            // Calculate the offset within the segment
            size_t segment_offset = (uint8_t*)ptr - (uint8_t*)segment_start;
            
            // Calculate the total offset
            mos total_offset = (i * memory->segment_size) + segment_offset;

            if (WASM_DEBUG_GET_OFFSET_POINTER) {
                ESP_LOGI("WASM3", "get_offset_pointer: converted %p to offset %u (segment %zu)", ptr, total_offset, i);
            }
            
            //todo: notify_memory_segment_access(memory, seg);  

            return total_offset;
        }
    }

    // If we didn't find the pointer in any segment, return the original pointer
    if (WASM_DEBUG_GET_OFFSET_POINTER) {
        ESP_LOGI("WASM3", "get_offset_pointer: pointer %p not found in segmented memory", ptr);
    }
    
    return (mos)ptr;
}

void notify_memory_segment_access(IM3Memory memory, MemorySegment* segment){
    #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
    if(segment->segment_page == NULL){
        ESP_LOGW("WASM3", "notify_memory_segment_access: memory segment page is NULL");
        //backtrace();
        return;
    }

    paging_notify_segment_access(memory->paging, segment->segment_page->segment_id);

    if(segment->data == NULL){
        ESP_LOGE("WASM3", "notify_memory_segment_access: segment data is NULL after notify_memory_segment_access");
        //todo: init now?
    }

    #endif
}

// Core pointer resolution functions
bool WASM_DEBUG_get_offset_pointer = WASM_DEBUG_ALL || (WASM_DEBUG && false);
ptr get_segment_pointer(IM3Memory memory, mos offset) {
    check_wdt_reset();    

    if(WASM_DEBUG_get_offset_pointer) ESP_LOGI("WASM3", "get_segment_pointer called with offset %llu", offset);    

    if (!memory || memory->firm != INIT_FIRM) {
        ESP_LOGE("WASM3", "get_segment_pointer: memory invalid");
        return (ptr)&ERROR_POINTER;
    }

    if(false && !IsValidMemoryAccess(memory, offset, 1)){ // this is pretty redundant
        return (ptr)offset;
    }
    
    // Calculate segment indices
    size_t segment_index = offset / memory->segment_size;
    size_t segment_offset = offset % memory->segment_size;
    
    // Validate segment
    if (segment_index >= memory->num_segments) {
        if(false){ // don't add new needed segments
            ESP_LOGE("WASM3", "add_segment_pointer: pointer outside segment limits: %llu > %llu", segment_index, memory->num_segments);
            return (ptr)&ERROR_POINTER;
        }

        // Try to grow memory if needed
        if (segment_index - memory->num_segments <= 2) {
            if (AddSegments(memory, segment_index + 1 - memory->num_segments) != NULL) {
                ESP_LOGE("WASM3", "add_segment_pointer: AddSegments failed");
                return (ptr)&ERROR_POINTER;
            }
        } else {
            return (ptr)&ERROR_POINTER;
        }
    }
    
    MemorySegment* seg = memory->segments[segment_index];
    if (!seg || seg->firm != INIT_FIRM){ 
        ESP_LOGE("WASM3", "add_segment_pointer: seg invalid");
        return (ptr)&ERROR_POINTER;
    }
    
    // Initialize segment if needed
    if (m3_alloc_on_segment_data && !seg->data) {
        if(seg->is_allocated){
            notify_memory_segment_access(memory, seg);
        }
        else {
            if(WASM_DEBUG_get_offset_pointer) ESP_LOGI("WASM3", "get_segment_pointer: requested data allocation of segment %lu", segment_index);
            seg = InitSegment(memory, seg, true);

            if(seg == NULL){
                ESP_LOGE("WASM3", "get_segment_pointer: failed init segment data");
                return (ptr)&ERROR_POINTER;
            }
        }
    }
    
    mos seg_offset = segment_offset;

    // Handle multi-segment chunks
    MemoryChunk* chunk = seg->first_chunk;
    while (chunk) {
        if (chunk->num_segments > 1) {
            size_t chunk_start = chunk->start_segment * memory->segment_size;
            size_t chunk_end = chunk_start;
            for (size_t i = 0; i < chunk->num_segments; i++) {
                chunk_end += chunk->segment_sizes[i];
            }
            
            if (offset >= chunk_start && offset < chunk_end) {
                // Calculate which segment of the chunk we're in
                size_t relative_offset = offset - chunk_start;
                size_t current_size = 0;
                for (size_t i = 0; i < chunk->num_segments; i++) {
                    if (relative_offset < current_size + chunk->segment_sizes[i]) {
                        seg = memory->segments[chunk->start_segment + i];
                        seg_offset = (relative_offset - current_size);

                        goto resolve;
                    }
                    current_size += chunk->segment_sizes[i];
                }
            }
        }
        chunk = chunk->next;
    }

    resolve: {
        if(WASM_SEGMENTED_MEM_LAZY_ALLOC){
            if(!seg->is_allocated){
                InitSegment(memory, seg, true);
            }
        }

        if(WASM_DEBUG_get_offset_pointer) {
            ESP_LOGI("WASM3", "get_segment_pointer: seg->is_allocated=%d, seg->data=%p",  seg->is_allocated, seg->data);
        }
            
        notify_memory_segment_access(memory, seg);

        if(WASM_DEBUG_get_offset_pointer) {
            ESP_LOGI("WASM3", "get_segment_pointer: (after notify) seg->is_allocated=%d, seg->data=%p", seg->is_allocated, seg->data);
        }

        if(WASM_DEBUG_get_offset_pointer) {
            ESP_LOGI("WASM3", "get_segment_pointer: pointer resolved with seg_offset: %lld", seg_offset);
            ESP_LOGI("WASM3", "get_segment_pointer: requested segment %d", seg->index);
            ESP_LOGI("WASM3", "get_segment_pointer: requested segment data index: %p", seg->data);
        }        

        return ((ptr)seg->data + seg_offset);
    }
}


DEBUG_TYPE WASM_DEBUG_m3_ResolvePointer = WASM_DEBUG_ALL || (WASM_DEBUG && true);
ptr m3_ResolvePointer(M3Memory* memory, mos offset) {
    #if TRACK_MEMACCESS
    ESP_LOGI("WASM3", "m3_ResolvePointer: requested offset %d", offset);
    #endif

    if(WASM_DEBUG_m3_ResolvePointer) ESP_LOGI("WASM3", "m3_ResolvePointer (mem: %p) called for ptr: %p", memory, offset);

    ptr resolved = (ptr)offset;
    if (is_ptr_valid((void*)offset)) {
        if(WASM_DEBUG_m3_ResolvePointer) ESP_LOGI("WASM3", "m3_ResolvePointer %p considered valid", offset);
        goto resolve;
    }
    
    if (!memory || memory->firm != INIT_FIRM) return (ptr)offset;
    
    resolved = get_segment_pointer(memory, offset);
    if (resolved == ERROR_POINTER) return (ptr)offset;
    
    resolve: {
        if(WASM_DEBUG_m3_ResolvePointer) ESP_LOGI("WASM3", "m3_ResolvePointer: original: %p, resolved: %p", offset, resolved);

        if (!is_ptr_valid((void*)resolved)) {
            ESP_LOGW("WASM3", "m3_ResolvePointer: resolved pointer is not valid %p %p", offset, resolved);
            //backtrace();
            return (ptr)offset;
        }    

        return resolved;
    }
}

int find_segment_index(MemorySegment** segments, int num_segments, MemorySegment* segment) {
    for (int i = 0; i < num_segments; i++) {
        if (segments[i] == segment) {
            return i;
        }
    }
    return -1;  // Se non viene trovato
}

// Memory initialization and growth
DEBUG_TYPE WASM_DEBUG_INITSEGMENT = WASM_DEBUG_ALL || (WASM_DEBUG && false);
MemorySegment* InitSegment(M3Memory* memory, MemorySegment* seg, bool initData) {
    if (memory == NULL || memory->firm != INIT_FIRM){ 
        ESP_LOGW("WASM", "InitSegment: memory not initialized");
        return NULL;
    }
    
    if (seg == NULL) {
        ESP_LOGW("WASM", "InitSegment: segment allocation on the run");
        seg = m3_Def_Malloc(sizeof(MemorySegment));
        if (seg == NULL) {
            ESP_LOGW("WASM", "InitSegment: failed to allocate memory segment");
            return NULL;
        }

        seg->index = find_segment_index(memory->segments, memory->num_segments, seg);
    }

    seg->firm = INIT_FIRM;

    #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
    if(seg->segment_page == NULL) {
        esp_err_t res = paging_notify_segment_creation(memory->paging, &seg->segment_page);
        if(res != ESP_OK) {
            ESP_LOGE("WASM3", "Failed paging_notify_segment_creation: %d", res);
            return NULL;
        }

        if(WASM_DEBUG_INITSEGMENT){
            ESP_LOGI("WASM3", "InitSegment: created new seg->segment_page: %p", seg->segment_page);
            ESP_LOGI("WASM3", "InitSegment: data: %p", &seg->data);
            ESP_LOGI("WASM3", "InitSegment: seg->segment_page->data: %p", &seg->segment_page->data);
        }

        seg->segment_page->data = &seg->data;
    }
    #endif 
    
    if (initData && !seg->data) {
        if(WASM_DEBUG_INITSEGMENT) ESP_LOGI("WASM", "InitSegment: allocating segment's data");
        seg->data = m3_Def_Malloc(memory->segment_size);
        if (seg->data == NULL) {
            ESP_LOGE("WASM", "InitSegment: segmente data allocate failed");
            return NULL;
        }
        
        seg->is_allocated = true;
        seg->size = memory->segment_size;
        seg->first_chunk = NULL;
        memory->total_allocated_size += memory->segment_size;
        
        #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
        paging_notify_segment_allocation(memory->paging, seg->segment_page, &seg->data);
        #endif        
    }
    
    return seg;
}

DEBUG_TYPE WASM_DEBUG_ADDSEGMENT = WASM_DEBUG_ALL || (WASM_DEBUG && false);
M3Result AddSegments(IM3Memory memory, size_t additional_segments) {
    if(WASM_DEBUG_ADDSEGMENT) ESP_LOGI("WASM3", "AddSegments: requested %zu segments", additional_segments);
    if (memory == NULL || memory->firm != INIT_FIRM) {
        ESP_LOGE("WASM3", "AddSegments: memory is not initialized");
        return m3Err_nullMemory;    
    }

    size_t new_num_segments = additional_segments == 0 ? (memory->num_segments + 1) : additional_segments;

    if(new_num_segments <= memory->num_segments) {
        if(WASM_DEBUG_ADDSEGMENT) ESP_LOGW("WASM3", "AddSegments: no needed to add more segments (req: %d, current: %d)", new_num_segments, memory->num_segments);
        return NULL;
    }

    size_t new_size = new_num_segments * sizeof(MemorySegment*);
    
    MemorySegment** new_segments = m3_Def_Realloc(memory->segments, new_size);
    if (!new_segments) {
        ESP_LOGE("WASM3", "AddSegments: realloc memory->segments failed");
        return m3Err_mallocFailed;
    }
    
    memory->segments = new_segments;
    
    // Initialize new segments
    for (size_t i = memory->num_segments; i < new_num_segments; i++) {
        memory->segments[i] = m3_Def_Malloc(sizeof(MemorySegment));

        if (!memory->segments[i]) {
            // Rollback on failure
            for (size_t j = memory->num_segments; j < i; j++) {
                m3_Def_Free(memory->segments[j]);
            }
            return m3Err_mallocFailed;
        }

        memory->segments[i]->index = i;
        
        void* seg = InitSegment(memory, memory->segments[i], false);
        if (seg == NULL) {
            ESP_LOGE("WASM3", "AddSegment: InitSegment %d failed", i);

            // Cleanup on failure
            for (size_t j = memory->num_segments; j <= i; j++) {
                m3_Def_Free(memory->segments[j]);
            }
            return m3Err_mallocFailed;
        }
    }
    
    memory->num_segments = new_num_segments;
    memory->total_size = memory->segment_size * new_num_segments;
    
    return m3Err_none;
}

const int WASM_M3_INIT_MEMORY_NUM_MALLOC_TESTS = 2;
IM3Memory m3_InitMemory(IM3Memory memory) {
    if (memory == NULL) return NULL;

    if(memory->firm == INIT_FIRM)
        return memory;
    
    memory->firm = INIT_FIRM;
    memory->segments = NULL;
    memory->num_segments = 0;
    memory->total_size = 0;
    memory->total_allocated_size = 0;
    memory->segment_size = WASM_SEGMENT_SIZE;
    memory->maxPages = M3Memory_MaxPages;
    memory->pageSize = M3Memory_PageSize;
    memory->total_requested_size = 0;
    
    // Initialize free chunks management
    memory->num_free_buckets = 32;
    memory->free_chunks = m3_Def_Malloc(memory->num_free_buckets * sizeof(MemoryChunk*));
    if (!memory->free_chunks) return NULL;
        
    #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
    segment_handlers_t handlers = {0};
    paging_init(&memory->paging, &handlers, memory->segment_size);
    if(WASM_DEBUG_M3_INIT_MEMORY) ESP_LOGI("WASM3", "m3_InitMemory: memory->paging: %p", memory->paging);
    #endif

    // Add initial segments
    M3Result result = AddSegments(memory, WASM_INIT_SEGMENTS);
    if (result != m3Err_none) {
        ESP_LOGE("WASM3", "m3_InitMemory: AddSegments failed");
        free(memory->free_chunks);
        return NULL;
    }

    if(WASM_M3_INIT_MEMORY_NUM_MALLOC_TESTS > 0){
        for(int i = 0; i < WASM_M3_INIT_MEMORY_NUM_MALLOC_TESTS; i++){
            if(WASM_DEBUG_M3_INIT_MEMORY) ESP_LOGI("WASM3", "m3_InitMemory: test m3_malloc num %d", i);
            void* testPtr = m3_malloc(memory, 1);

            if(i != 0 && testPtr == 0){
                ESP_LOGE("WASM3", "m3_InitMemory: test m3_malloc failed (given %d)", testPtr);
            }

            if(WASM_DEBUG_M3_INIT_MEMORY) PRINT_PTR(testPtr);
        }
    }
    
    return memory;
}

IM3Memory m3_NewMemory(){
    IM3Memory memory = m3_Def_AllocStruct (M3Memory);

    m3_InitMemory(memory);

    return memory;
}

DEBUG_TYPE WASM_DEBUG_TOP_MEMORY = WASM_DEBUG_ALL || (WASM_DEBUG && false);
void FreeMemory(IM3Memory memory) {
    if (!memory) return;
    if (WASM_DEBUG_TOP_MEMORY) ESP_LOGI("WASM3", "FreeMemory called");

    // Verifica integrità della memoria
    if (!IsValidMemory(memory) || memory->segment_size != WASM_SEGMENT_SIZE) {
        if (WASM_DEBUG_TOP_MEMORY) ESP_LOGW("WASM3", "FreeMemory: invalid memory structure");
        return;
    }

    // Prima libera le free lists
    if (memory->free_chunks) {
        for (size_t i = 0; i < memory->num_free_buckets; i++) {
            MemoryChunk* chunk = memory->free_chunks[i];
            while (chunk) {
                MemoryChunk* next = chunk->next;
                if (chunk->segment_sizes) {
                    m3_Def_Free(chunk->segment_sizes);
                }
                chunk = next;
            }
        }
        m3_Def_Free(memory->free_chunks);
        memory->free_chunks = NULL;
    }

    if (is_ptr_valid(memory->segments)) {
        // Libera tutti i segmenti e le loro strutture
        for (size_t i = 0; i < memory->num_segments; i++) {
            if (WASM_DEBUG_TOP_MEMORY) ESP_LOGI("WASM3", "FreeMemory: processing segment %zu", i);
            
            MemorySegment* segment = memory->segments[i];
            if (!is_ptr_valid(segment)) {
                if (WASM_DEBUG_TOP_MEMORY) ESP_LOGI("WASM3", "FreeMemory: segment %zu not valid", i);
                continue;
            }

            if (segment->data) {
                // Libera segment_sizes di ogni chunk nel segmento
                // ma solo per i chunk che iniziano in questo segmento
                MemoryChunk* chunk = segment->first_chunk;
                while (chunk) {
                    if (chunk->start_segment == i && chunk->segment_sizes) {
                        if (WASM_DEBUG_TOP_MEMORY) {
                            ESP_LOGI("WASM3", "FreeMemory: freeing chunk segment_sizes at segment %zu", i);
                        }
                        m3_Def_Free(chunk->segment_sizes);
                        chunk->segment_sizes = NULL;
                    }
                    chunk = chunk->next;
                }

                if (segment->is_allocated) {
                    if (WASM_DEBUG_TOP_MEMORY) {
                        ESP_LOGI("WASM3", "FreeMemory: freeing segment %zu data", i);
                    }
                    m3_Def_Free(segment->data);
                    segment->data = NULL;
                }
            }

            m3_Def_Free(segment);
            memory->segments[i] = NULL;
        }

        // Libera l'array dei segmenti
        if (WASM_DEBUG_TOP_MEMORY) ESP_LOGI("WASM3", "FreeMemory: freeing segments array");
        m3_Def_Free(memory->segments);
        memory->segments = NULL;
    }

    // Resetta tutti i contatori e gli stati
    memory->num_segments = 0;
    memory->total_size = 0;
    memory->total_allocated_size = 0;
    memory->total_requested_size = 0;
    memory->maxPages = 0;
    memory->num_free_buckets = 0;
    memory->firm = 0;  // Invalida la struttura della memoria

    #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
    paging_deinit(memory->paging);
    #endif

    if (WASM_DEBUG_TOP_MEMORY) ESP_LOGI("WASM3", "FreeMemory completed");
}

bool IsValidMemory(IM3Memory memory) {
    if(memory == NULL || memory->firm != INIT_FIRM) return false;
    return memory;
}

M3Result GrowMemory(M3Memory* memory, size_t additional_size) {
    if (!memory) return m3Err_nullMemory;
    
    size_t new_total = memory->total_size + additional_size;
    if (new_total > memory->maxPages * memory->segment_size) {
        return m3Err_memoryLimit;
    }
    
    size_t additional_segments = (additional_size +  memory->segment_size - 1) /  memory->segment_size;
    return AddSegments(memory, additional_segments);
}

// Memory operations
DEBUG_TYPE WASM_DEBUG_IsValidMemoryAccess = WASM_DEBUG_ALL || (WASM_DEBUG && false);
bool IsValidMemoryAccess(IM3Memory memory, mos offset, size_t size) {
    check_wdt_reset();

    if(WASM_DEBUG_IsValidMemoryAccess) ESP_LOGI("WASM3", "IsValidMemoryAccess called with memory=%p, offset=%p, size=%d", memory, offset, size);

    if (!memory || !memory->segments) goto isNotSegMem;

    if(WASM_DEBUG_IsValidMemoryAccess) {
        ESP_LOGI("WASM3", "IsValidMemoryAccess: memory->total_size=%zu, offset=%zu", memory->total_size, offset);
    }    

    if (offset + size > memory->total_size) goto isNotSegMem;
    
    size_t start_segment = offset / memory->segment_size;
    size_t end_segment = (offset + size - 1) / memory->segment_size;

    if(start_segment > memory->num_segments || end_segment > memory->num_segments){
        return false;
    }
    
    // Verify all needed segments exist and are initialized
    for (size_t i = start_segment; i <= end_segment; i++) {
        if (i >= memory->num_segments) goto isNotSegMem;
        
        MemorySegment* seg = memory->segments[i];
        if (!seg) goto isNotSegMem;
        
        // Check for multi-segment chunks
        if (seg->first_chunk) {
            MemoryChunk* chunk = seg->first_chunk;
            size_t chunk_segment_id = i;
            while (chunk) {
                if (chunk->num_segments > 1) {
                    size_t chunk_start = chunk->start_segment * memory->segment_size;
                    size_t chunk_end = chunk_start;
                    for (size_t j = 0; j < chunk->num_segments; j++) {
                        chunk_end += chunk->segment_sizes[j];
                    }
                    
                    if (offset >= chunk_start && offset + size <= chunk_end) {
                        MemorySegment* chunk_segment = memory->segments[chunk_segment_id];

                        if(WASM_SEGMENTED_MEM_LAZY_ALLOC){
                            if(!seg->is_allocated){
                                InitSegment(memory, chunk_segment, true);
                            }
                        }

                        //notify_memory_segment_access(memory, chunk_segment);
                        return true;  // Access is within a valid multi-segment chunk
                    }
                }
                chunk = chunk->next;
                chunk_segment_id++;
            }
        }
    }
    
    //notify_memory_segment_access(memory, memory->segments[start_segment]);
    return true;

    isNotSegMem: {    
        mos* ptr = (mos*)offset;
        if(!is_ptr_valid(ptr)){
            //ESP_LOGW("WASM3", "IsValidMemoryAccess: is not segmented pointer, and both not valid pointer");
            //backtrace();
            return true;
        }

        return false;
    }
}

////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////


static mos ptr_to_offset(M3Memory* memory, void* ptr) {
    if (!memory || !ptr) return 0;
    
    for (size_t i = 0; i < memory->num_segments; i++) {
        MemorySegment* seg = memory->segments[i];
        if (!seg || !seg->data) continue;
        
        // Verifica se il puntatore è all'interno di questo segmento
        if (ptr >= seg->data && ptr < (void*)((char*)seg->data + seg->size)) {
            // Se il puntatore è all'interno del segmento, calcola l'offset
            size_t segment_base_offset = i * memory->segment_size;
            size_t intra_segment_offset = (char*)ptr - (char*)seg->data;
            
            // Se stiamo ritornando un offset per i dati (non per il MemoryChunk stesso)
            // dobbiamo sottrarre la dimensione dell'header dal calcolo dell'offset
            if (intra_segment_offset >= sizeof(MemoryChunk)) {
                size_t data_offset = intra_segment_offset - sizeof(MemoryChunk);
                return segment_base_offset + data_offset;
            }
            
            //todo: force segment load
            //notify_memory_segment_access(memory, memory->segments[segment_base_offset]);

            return segment_base_offset + intra_segment_offset;
        }
    }
    
    return 0;
}

////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////

DEBUG_TYPE WASM_DEBUG_GenericMemory = WASM_DEBUG_ALL || (WASM_DEBUG && true);

// Helper function to create a new chunk metadata structure
static MemoryChunk* create_chunk(size_t size, uint16_t start_segment, uint16_t num_segments) {

    if(WASM_DEBUG_GenericMemory){
        ESP_LOGI("WASM3", "Going to create chunk %d, %d, %d", size, start_segment, num_segments);
    }

    MemoryChunk* chunk = m3_Def_Malloc(sizeof(MemoryChunk));
    if (!chunk) return NULL;
    
    chunk->size = size;
    chunk->is_free = false;
    chunk->next = NULL;
    chunk->prev = NULL;
    chunk->num_segments = num_segments;
    chunk->start_segment = start_segment;
    
    // Allocate segment sizes array
    chunk->segment_sizes = m3_Def_Malloc(num_segments * sizeof(size_t));
    if (!chunk->segment_sizes) {
        m3_Def_Free(chunk);
        return NULL;
    }
    
    return chunk;
}

// Helper function to free a chunk and its associated metadata
static void free_chunk(MemoryChunk* chunk) {
    if (!chunk) return;
    if (chunk->segment_sizes) {
        m3_Def_Free(chunk->segment_sizes);
    }
    m3_Def_Free(chunk);
}

ptr m3_malloc(M3Memory* memory, size_t size) {
    if (!memory || memory->firm != INIT_FIRM || size == 0) {
        return NULL;
    }

    // Calculate total size needed with alignment
    size_t total_size = (size + (WASM_CHUNK_SIZE-1)) & ~(WASM_CHUNK_SIZE-1);
    size_t bucket = log2(total_size);
    
    // First try to find a suitable free chunk
    MemoryChunk* found_chunk = NULL;
    if (bucket < memory->num_free_buckets) {
        MemoryChunk** curr = &memory->free_chunks[bucket];
        while (*curr) {
            if ((*curr)->size >= total_size) {
                found_chunk = *curr;
                *curr = found_chunk->next;
                found_chunk->is_free = false;
                break;
            }
            curr = &(*curr)->next;
        }
    }
    
    // If no free chunk found, create a new one
    if (!found_chunk) {
        // Calculate number of segments needed
        size_t segments_needed = (total_size + memory->segment_size - 1) / memory->segment_size;
        if (segments_needed == 0) segments_needed = 1;
        
        // Find or allocate required segments
        size_t start_segment = memory->num_segments;
        for (size_t i = 0; i < memory->num_segments; i++) {
            if (!memory->segments[i]->data) {
                start_segment = i;
                break;
            }
        }
        
        // Add new segments if needed
        if (start_segment + segments_needed > memory->num_segments) {
            if (AddSegments(memory, start_segment + segments_needed) != m3Err_none) {
                ESP_LOGE("WASM3", "m3_malloc: Failed to add segments");
                return NULL;
            }
        }
        
        // Create new chunk metadata
        found_chunk = create_chunk(total_size, start_segment, segments_needed);
        if (!found_chunk) return NULL;
        
        // Initialize segments and set up chunk sizes
        size_t remaining_size = total_size;
        for (size_t i = 0; i < segments_needed; i++) {
            MemorySegment* seg = memory->segments[start_segment + i];
            
            // Initialize segment if needed
            if (!seg->data) {
                if(seg->is_allocated){
                    //notify_memory_segment_access(memory, seg); 
                }
                else {
                    if (InitSegment(memory, seg, true) == NULL) {
                        free_chunk(found_chunk);
                        ESP_LOGE("WASM3", "m3_malloc: Failed to init segment");
                        return NULL;
                    }
                }
            }
            
            // Calculate size for this segment
            size_t segment_size = MIN(remaining_size, memory->segment_size);
            found_chunk->segment_sizes[i] = segment_size;
            remaining_size -= segment_size;
            
            // Link chunk to segment
            if (i == 0) {
                found_chunk->next = seg->first_chunk;
                if (seg->first_chunk) {
                    seg->first_chunk->prev = found_chunk;
                }
                seg->first_chunk = found_chunk;
            }
        }
    }
    
    // Calculate return offset
    mos base_offset = found_chunk->start_segment * memory->segment_size;
    memory->total_requested_size += size;
    
    return (ptr)base_offset;
}

void m3_free(M3Memory* memory, ptr ptr) {
    if (!memory || !ptr) return;
    
    // Get chunk info
    ChunkInfo info = get_chunk_info(memory, ptr);
    MemoryChunk* chunk = info.chunk;
    if (!chunk) return;
    
    // Remove chunk from segment lists
    MemorySegment* start_seg = memory->segments[chunk->start_segment];
    if (start_seg->first_chunk == chunk) {
        start_seg->first_chunk = chunk->next;
    }
    
    if (chunk->prev) chunk->prev->next = chunk->next;
    if (chunk->next) chunk->next->prev = chunk->prev;
    
    // Add to appropriate free list
    size_t bucket = log2(chunk->size);
    if (bucket < memory->num_free_buckets) {
        chunk->is_free = true;
        chunk->next = memory->free_chunks[bucket];
        memory->free_chunks[bucket] = chunk;
    } else {
        // Chunk too large for free lists, just delete it
        free_chunk(chunk);
    }
    
    // Try to collect empty segments
    m3_collect_empty_segments(memory);
}

ptr m3_realloc(M3Memory* memory, ptr offset, size_t new_size) {
    if (!memory) return NULL;
    if (!offset) return m3_malloc(memory, new_size);
    if (new_size == 0) {
        m3_free(memory, offset);
        return NULL;
    }
    
    // Get current chunk info
    ChunkInfo info = get_chunk_info(memory, offset);
    MemoryChunk* old_chunk = info.chunk;
    if (!old_chunk) return NULL;
    
    // Calculate new total size needed
    size_t total_new_size = (new_size + (WASM_CHUNK_SIZE-1)) & ~(WASM_CHUNK_SIZE-1);
    
    // If shrinking, just update the size
    if (total_new_size <= old_chunk->size) {
        old_chunk->size = total_new_size;
        return offset;
    }
    
    // Otherwise allocate new chunk and copy data
    ptr new_ptr = m3_malloc(memory, new_size);
    if (!new_ptr) return NULL;
    
    m3_memcpy(memory, new_ptr, offset, MIN(old_chunk->size, new_size));
    m3_free(memory, offset);
    
    return new_ptr;
}

// Helper function to validate and get chunk information
ChunkInfo get_chunk_info(M3Memory* memory, void* ptr) {
    ChunkInfo result = { NULL, 0 };
    if (!memory || !ptr) return result;
    
    // Calculate segment index
    mos offset = (mos)ptr;
    size_t segment_index = offset / memory->segment_size;
    if (segment_index >= memory->num_segments) return result;
    
    MemorySegment* seg = memory->segments[segment_index];
    if (!seg) return result;
    
    // Search for chunk that contains this address
    MemoryChunk* current = seg->first_chunk;
    while (current) {
        mos chunk_start = current->start_segment * memory->segment_size;
        mos chunk_end = chunk_start;
        
        // Calculate total size across segments
        for (size_t i = 0; i < current->num_segments; i++) {
            chunk_end += current->segment_sizes[i];
        }
        
        if (offset >= chunk_start && offset < chunk_end) {
            result.chunk = current;
            result.base_offset = chunk_start;
            break;
        }
        
        current = current->next;
    }
    
    return result;
}

///
///
///

// Memory copy function that handles segmented memory
DEBUG_TYPE WASM_DEBUG_m3_memcpy = WASM_DEBUG_ALL || (WASM_DEBUG && true);
M3Result m3_memcpy(M3Memory* memory, void* dest, const void* src, size_t n) {
    // Early validation
    if (!dest || !src || !n) {
        ESP_LOGW("WASM3", "m3_memcpy: NULL pointer or zero size");
        return m3Err_malformedData;
    }

    // Handle invalid memory
    if (!IsValidMemory(memory)) {
        ESP_LOGE("WASM3", "m3_memcpy: Invalid memory: %p", memory);
        return m3Err_malformedData;
    }

    // Check if pointers are segmented
    bool dest_is_segmented = IsValidMemoryAccess(memory, CAST_PTR dest, n);
    bool src_is_segmented = IsValidMemoryAccess(memory, CAST_PTR src, n);

    if(WASM_DEBUG_m3_memcpy){
        ESP_LOGI("WASM3", "dest_is_segmented: %d", dest_is_segmented);
        ESP_LOGI("WASM3", "src_is_segmented: %d", src_is_segmented);
    }

    if(!dest_is_segmented && !src_is_segmented) {
        memcpy(dest, src, n);
    }

    size_t bytes_remaining = n;
    const void* curr_src = src;
    void* curr_dest = dest;

    while (bytes_remaining > 0) {
        // Resolve pointers if they're segmented
        void* real_dest = dest_is_segmented ? m3_ResolvePointer(memory, CAST_PTR curr_dest) : curr_dest;
        void* real_src = src_is_segmented ? m3_ResolvePointer(memory, CAST_PTR curr_src) : curr_src;

        if ((dest_is_segmented && real_dest == ERROR_POINTER) || 
            (src_is_segmented && real_src == ERROR_POINTER)) {
            ESP_LOGE("WASM3", "m3_memcpy: Failed to resolve pointer - src: %p, dest: %p", 
                     curr_src, curr_dest);
            return m3Err_malformedData;
        }

        // Calculate copy size based on segment boundaries for segmented pointers
        size_t copy_size = bytes_remaining;
        
        if (dest_is_segmented) {
            size_t dest_to_boundary = memory->segment_size - (CAST_PTR curr_dest % memory->segment_size);
            copy_size = MIN(copy_size, dest_to_boundary);
        }
        
        if (src_is_segmented) {
            size_t src_to_boundary = memory->segment_size - (CAST_PTR curr_src % memory->segment_size);
            copy_size = MIN(copy_size, src_to_boundary);
        }        

        // Perform copy for current chunk  
        if(WASM_DEBUG_GenericMemory){   
            ESP_LOGI("WASM3", "memcpy(%p, %p, %d)", real_dest, real_src, copy_size); 

            log_bytes(real_dest, copy_size);
            log_bytes(real_src, copy_size);

            waitForIt(); 
        }
        memcpy(real_dest, real_src, copy_size);

        // Update pointers and remaining count
        curr_src = (const char*)curr_src + copy_size;
        curr_dest = (char*)curr_dest + copy_size;
        bytes_remaining -= copy_size;
    }

    return NULL;
}

// Memory set function that handles segmented memory
M3Result m3_memset(M3Memory* memory, void* ptr, int value, size_t n) {
    // Early validation
    if (!ptr || !n) {
        //ESP_LOGE("WASM3", "m3_memset: NULL pointer or zero size"); // study about this case?
        return m3Err_malformedData;
    }    

    // Handle invalid memory
    if (!IsValidMemory(memory)) {
        ESP_LOGE("WASM3", "m3_memset: Invalid memory: %p", memory);
        return m3Err_malformedData;
    }

    if(!IsValidMemoryAccess(memory, (mos)ptr, n)){
        memset(ptr, value, n);
        return NULL;
    }

    size_t bytes_remaining = n;
    void* curr_ptr = ptr;

    while (bytes_remaining > 0) {
        // Resolve current pointer
        void* real_ptr = m3_ResolvePointer(memory, CAST_PTR curr_ptr);
        if (real_ptr == ERROR_POINTER) {
            ESP_LOGE("WASM3", "m3_memset: Failed to resolve pointer: %p", curr_ptr);
            return m3Err_malformedData;
        }

        // Calculate size until next chunk boundary
        size_t to_boundary = memory->segment_size - ((mos)curr_ptr % memory->segment_size);
        size_t to_set = MIN(to_boundary, bytes_remaining);

        // Perform memset for current chunk
        memset(real_ptr, value, to_set);

        // Update pointer and remaining count
        curr_ptr = (char*)curr_ptr + to_set;
        bytes_remaining -= to_set;
    }

    return NULL;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

void* m3SegmentedMemAccess(IM3Memory memory, m3stack_t offset, size_t size) {
    return (void*)m3_ResolvePointer(memory, (mos)(uintptr_t)offset);
}


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
//=================== GARBAGE COLLECTOR =============================///
////////////////////////////////////////////////////////////////////////

// Prototipi di funzioni helper
static bool is_segment_empty(IM3Memory memory, MemorySegment* segment);
static void deallocate_segment_data(IM3Memory memory, MemorySegment* segment);

void m3_collect_empty_segments(M3Memory* memory) {
    if (!memory || memory->firm != INIT_FIRM) {
        ESP_LOGW("WASM3", "m3_collect_empty_segments: invalid memory");
        return;
    }

    if (WASM_DEBUG_SEGMENTED_MEMORY_ALLOC) {
        ESP_LOGI("WASM3", "Starting empty segments collection");
    }

    size_t freed_segments = 0;
    size_t freed_bytes = 0;

    // Mantieni almeno un segmento (il primo)
    for (size_t i = 1; i < memory->num_segments; i++) {
        MemorySegment* segment = memory->segments[i];
        
        if (!segment || !segment->data) {
            continue;
        }

        if (is_segment_empty(memory, segment) && segment->data) {
            if (WASM_DEBUG_SEGMENTED_MEMORY_ALLOC) {
                ESP_LOGI("WASM3", "Freeing empty segment %zu", i);
            }

            // Dealloca i dati del segmento
            deallocate_segment_data(memory, segment);
            freed_segments++;
            freed_bytes += segment->size;
            
            // Reset dei campi del segmento ma mantieni la struttura
            segment->data = NULL;
            segment->is_allocated = false;
            segment->size = 0;
            segment->first_chunk = NULL;
        }
    }

    if (WASM_DEBUG_SEGMENTED_MEMORY_ALLOC) {
        ESP_LOGI("WASM3", "Garbage collection completed: freed %zu segments (%zu bytes)", 
                 freed_segments, freed_bytes);
        
        // Log dello stato della memoria dopo la GC
        size_t total_allocated = 0;
        size_t empty_segments = 0;
        for (size_t i = 0; i < memory->num_segments; i++) {
            if (memory->segments[i] && memory->segments[i]->data) {
                total_allocated += memory->segments[i]->size;
            } else {
                empty_segments++;
            }
        }
        ESP_LOGI("WASM3", "Memory status after GC: %zu empty segments, %zu bytes still allocated",
                 empty_segments, total_allocated);
    }

    // Aggiorna il contatore della memoria totale allocata
    memory->total_allocated_size -= freed_bytes;
}

static bool is_segment_empty(IM3Memory memory, MemorySegment* segment) {
    if (!segment || !segment->data) {
        return true;
    }

    // Verifica se ci sono chunk attivi
    MemoryChunk* current = segment->first_chunk;
    while (current) {
        if (!current->is_free) {
            // Trovato un chunk attivo
            return false;
        }
        current = current->next;
    }

    // Verifica che nessun chunk multi-segmento di altri segmenti si estenda in questo
    MemoryChunk** free_chunks = memory->free_chunks;
    size_t num_buckets = memory->num_free_buckets;

    for (size_t i = 0; i < num_buckets; i++) {
        MemoryChunk* chunk = free_chunks[i];
        while (chunk) {
            if (chunk->num_segments > 1) {
                // Calcola il range di segmenti occupati da questo chunk
                size_t end_segment = chunk->start_segment + chunk->num_segments - 1;
                
                // Se questo segmento cade nel range del chunk multi-segmento
                if (segment->index >= chunk->start_segment && 
                    segment->index <= end_segment) {
                    return false;
                }
            }
            chunk = chunk->next;
        }
    }

    return true;
}

static void deallocate_segment_data(IM3Memory memory, MemorySegment* segment) {
    if (!segment || !segment->data) {
        return;
    }

    // Libera tutti i segment_sizes arrays dei chunk nel segmento
    MemoryChunk* current = segment->first_chunk;
    while (current) {
        if (current->segment_sizes) {
            m3_Def_Free(current->segment_sizes);
            current->segment_sizes = NULL;
        }
        current = current->next;
    }

    // Libera i dati del segmento
    m3_Def_Free(segment->data);
    segment->data = NULL;
    memory->total_allocated_size -= segment->size;
    segment->size = 0;
    segment->is_allocated = false;
    segment->first_chunk = NULL;

    #if WASM_SEGMENTED_MEM_ENABLE_HE_PAGES
    paging_notify_segment_deallocation(memory->paging, segment->segment_page->segment_id);
    #endif

    if (WASM_DEBUG_SEGMENTED_MEMORY_ALLOC) {
        ESP_LOGI("WASM3", "Deallocated segment data at index %zu", segment->index);
    }
}

// Helper per verificare se un segmento è parte di un chunk multi-segmento attivo
static bool is_part_of_active_multisegment(M3Memory* memory, size_t segment_index) {
    for (size_t i = 0; i < memory->num_segments; i++) {
        MemorySegment* seg = memory->segments[i];
        if (!seg || !seg->data) continue;

        MemoryChunk* chunk = seg->first_chunk;
        while (chunk) {
            if (!chunk->is_free && chunk->num_segments > 1) {
                size_t end_segment = chunk->start_segment + chunk->num_segments - 1;
                if (segment_index >= chunk->start_segment && 
                    segment_index <= end_segment) {
                    return true;
                }
            }
            chunk = chunk->next;
        }
    }
    return false;
}

////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
///// Memory chunks

// Funzione helper per ottenere solo il chunk
MemoryChunk* get_chunk(M3Memory* memory, void* ptr) {
    return get_chunk_info(memory, ptr).chunk;
}

// Funzione helper per ottenere solo l'offset base
mos get_chunk_base_offset(M3Memory* memory, void* ptr) {
    return get_chunk_info(memory, ptr).base_offset;
}