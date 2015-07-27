#include "hash.h"

int hf_crc32(const char *buf)
{
    static const unsigned long crc_table[256] =
    {
        0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
        0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
        0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
        0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
        0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
        0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
        0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
        0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
        0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
        0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
        0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
        0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
        0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
        0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
        0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
        0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
        0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
        0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
        0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
        0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
        0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
        0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
        0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
        0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
        0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
        0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
        0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
        0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
        0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
        0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
        0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
        0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
        0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
        0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
        0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
        0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
        0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
    };
    
    int crc32 = 0;
    size_t i = 0;
    size_t length = strlen(buf);
    
    /** accumulate crc32 for buffer **/
    crc32 = 0 ^ 0xFFFFFFFF;
    for (; i < length; i++)
    {
        crc32 = (crc32 >> 8) ^ crc_table[(crc32 ^ buf[i]) & 0xFF];
    }
    
    return crc32;
}


uint32_t hf_fnva(const char *buf)
{
    uint32_t hval = 0;
    unsigned char *s = (unsigned char *)buf;
    while (*s)
    {
        hval ^= (u_int32_t)*s++;
        hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    }
    
    return hval;
}


static int hashfunc(const char *buf, unsigned int size)
{    
    return (hf_crc32(buf) ^ 0xFFFFFFFF) % size;
}


/*
 * Create a hashmap with the requested number of buckets.  If "nbuckets" is
 * not greater than zero a NULL is returned; otherwise, a _token_ to the
 * hashmap is returned.
 *
 * NULLs are also returned if memory could not be allocated for hashmap.
 */
hashmap_t hashmap_create(unsigned int nbuckets)
{
    struct hashmap_s *ptr;

    if (nbuckets == 0)
        return NULL;

    ptr = (struct hashmap_s *) calloc(1, sizeof (struct hashmap_s));
    if (!ptr)
        return NULL;

    ptr->size = nbuckets;
    ptr->buckets = (struct hashbucket_s *) calloc(nbuckets, sizeof (struct hashbucket_s));
    if (!ptr->buckets) 
    {
        free (ptr);
        return NULL;
    }
    
    /* This points to "one" past the end of the hashmap. */
    ptr->end_iterator = 0;

    return ptr;
}



/*
 * Follow the chain of hashentries and delete them (including the data and
 * the key.)
 *
 * Returns: 0 if the function completed successfully
 *          negative number is returned if "entry" was NULL
 */
static int delete_hashbucket(struct hashbucket_s *bucket)
{
    struct hashentry_s *nextptr;
    struct hashentry_s *ptr;

    if (bucket == NULL || bucket->head == NULL)
        return -EINVAL;

    ptr = bucket->head;
    while (ptr) 
    {
        nextptr = ptr->next;

        free (ptr->key);
        free (ptr->data);
        free (ptr);

        ptr = nextptr;
    }

    return 0;
}


/*
 * Deletes a hashmap.  All the key/data pairs are also deleted.
 *
 * Returns: 0 on success
 *          negative if a NULL "map" was supplied
 */
int hashmap_delete(hashmap_t map)
{
    unsigned int i;

    if (map == NULL)
        return -EINVAL;

    for (i = 0; i != map->size; i++) 
    {
        if (map->buckets[i].head != NULL) 
            delete_hashbucket(&map->buckets[i]);
    }

    free(map->buckets);
    free(map);

    return 0;
}


/*
 * Inserts a NULL terminated string (as the key), plus any arbitrary "data"
 * of "len" bytes.  Both the key and the data are copied, so the original
 * key/data must be freed to avoid a memory leak.
 * The "data" must be non-NULL and "len" must be greater than zero.  You
 * cannot insert NULL data in association with the key.
 *
 * Returns: 0 on success
 *          negative number if there are errors
 */
int hashmap_insert(hashmap_t map, const char *key, const void *data, size_t len)
{
    struct hashentry_s *ptr;
    int hash;
    char *key_copy;
    void *data_copy;

    assert(map != NULL);
    assert(key != NULL);
    assert(data != NULL);
    assert(len > 0);

    if (map == NULL || key == NULL)
        return -EINVAL;

    if (!data || len < 1)
        return -ERANGE;

    hash = hashfunc(key, map->size);
    if (hash < 0)
        return hash;

    /*
     * First make copies of the key and data in case there is a memory
     * problem later.
     */
    key_copy = strdup(key);
    if (!key_copy)
        return -ENOMEM;

    data_copy = malloc(len);
    if (!data_copy) 
    {
        free(key_copy);
        return -ENOMEM;
    }

    memcpy(data_copy, data, len);
    ptr = (struct hashentry_s *) malloc(sizeof(struct hashentry_s));
    if (!ptr) 
    {
        free(key_copy);
        free(data_copy);
        return -ENOMEM;
    }

    ptr->key = key_copy;
    ptr->data = data_copy;
    ptr->len = len;

    /*
    * Now add the entry to the end of the bucket chain.
    */
    ptr->next = NULL;
    ptr->prev = map->buckets[hash].tail;
    if (map->buckets[hash].tail)
        map->buckets[hash].tail->next = ptr;

    map->buckets[hash].tail = ptr;
    if (!map->buckets[hash].head)
        map->buckets[hash].head = ptr;

    map->end_iterator++;
    return 0;
}


/*
 * Get an iterator to the first entry.
 *
 * Returns: an negative value upon error.
 */
hashmap_iter hashmap_first(hashmap_t map)
{
    assert(map != NULL);

    if (!map)
        return -EINVAL;

    if (map->end_iterator == 0)
        return -1;
    else
        return 0;
}


/*
 * Checks to see if the iterator is pointing at the "end" of the entries.
 *
 * Returns: 1 if it is the end
 *          0 otherwise
 */
int hashmap_is_end(hashmap_t map, hashmap_iter iter)
{
    assert(map != NULL);
    assert(iter >= 0);

    if (!map || iter < 0)
        return -EINVAL;

    if (iter == map->end_iterator)
        return 1;
    else
        return 0;
}


/*
 * Return a "pointer" to the first instance of the particular key.  It can
 * be tested against hashmap_is_end() to see if the key was not found.
 *
 * Returns: negative upon an error
 *          an "iterator" pointing at the first key
 *          an "end-iterator" if the key wasn't found
 */
hashmap_iter hashmap_find(hashmap_t map, const char *key)
{
    unsigned int i;
    hashmap_iter iter = 0;
    struct hashentry_s *ptr;

    assert(map != NULL);
    assert(key != NULL);

    if (!map || !key)
        return -EINVAL;

    /*
    * Loop through all the keys and look for the first occurrence
    * of a particular key.
    */
    for (i = 0; i != map->size; i++) 
    {
        ptr = map->buckets[i].head;

        while (ptr) 
        {
            if (strcmp(ptr->key, key) == 0)
                return iter;

            iter++;
            ptr = ptr->next;
        }
    }

    return iter;
}


/*
 * Retrieve the data associated with a particular iterator.
 *
 * Returns: the length of the data block upon success
 *          negative upon error
 */
ssize_t hashmap_return_entry(hashmap_t map, hashmap_iter iter, char **key, void **data)
{
    unsigned int i;
    struct hashentry_s *ptr;
    hashmap_iter count = 0;

    assert(map != NULL);
    assert(iter >= 0);
    assert(iter != map->end_iterator);
    assert(key != NULL);
    assert(data != NULL);

    if (!map || iter < 0 || !key || !data)
        return -EINVAL;

    for (i = 0; i != map->size; i++) 
    {
        ptr = map->buckets[i].head;
        while (ptr) 
        {
            if (count == iter) 
            {
                *key = ptr->key;
                *data = ptr->data;
                return ptr->len;
            }

            ptr = ptr->next;
            count++;
        }
    }

    return -EFAULT;
}


/*
 * Searches for _any_ occurrences of "key" within the hashmap.
 *
 * Returns: negative upon an error
 *          zero if no key is found
 *          count found
 */
ssize_t hashmap_search(hashmap_t map, const char *key)
{
    int hash;
    struct hashentry_s *ptr;
    ssize_t count = 0;

    if (map == NULL || key == NULL)
        return -EINVAL;

    hash = hashfunc(key, map->size);
    if (hash < 0)
        return hash;

    ptr = map->buckets[hash].head;

    /* All right, there is an entry here, now see if it's the one we want */
    while (ptr) 
    {
        if (strcmp(ptr->key, key) == 0)
            ++count;

        /* This entry didn't contain the key; move to the next one */
        ptr = ptr->next;
    }

    return count;
}


/*
 * Get the first entry (assuming there is more than one) for a particular
 * key.  The data MUST be non-NULL.
 *
 * Returns: negative upon error
 *          zero if no entry is found
 *          length of data for the entry
 */
ssize_t hashmap_entry_by_key(hashmap_t map, const char *key, void **data)
{
    int hash;
    struct hashentry_s *ptr;

    if (!map || !key || !data)
        return -EINVAL;

    hash = hashfunc(key, map->size);
    if (hash < 0)
        return hash;

    ptr = map->buckets[hash].head;
    while (ptr) 
    {
        if (strcmp(ptr->key, key) == 0) 
        {
            *data = ptr->data;
            return ptr->len;
        }

        ptr = ptr->next;
    }

    return 0;
}


/*
 * Go through the hashmap and remove the particular key.
 * NOTE: This will invalidate any iterators which have been created.
 *
 * Remove: negative upon error
 *         0 if the key was not found
 *         positive count of entries deleted
 */
ssize_t hashmap_remove(hashmap_t map, const char *key)
{
    int hash;
    struct hashentry_s *ptr, *next;
    short int deleted = 0;

    if (map == NULL || key == NULL)
        return -EINVAL;

    hash = hashfunc(key, map->size);
    if (hash < 0)
        return hash;

    ptr = map->buckets[hash].head;
    while (ptr) 
    {
        if (strcmp(ptr->key, key) == 0) 
        {         
            /*
            * Found the data, now need to remove everything
            * and update the hashmap.
            */
            next = ptr->next;

            if (ptr->prev)
                ptr->prev->next = ptr->next;

            if (ptr->next)
                ptr->next->prev = ptr->prev;

            if (map->buckets[hash].head == ptr)
                map->buckets[hash].head = ptr->next;
            
            if (map->buckets[hash].tail == ptr)
                map->buckets[hash].tail = ptr->prev;

            free(ptr->key);
            free(ptr->data);
            free(ptr);

            ++deleted;
            --map->end_iterator;

            ptr = next;
            continue;
        }

        /* This entry didn't contain the key; move to the next one */
        ptr = ptr->next;
    }

    /* The key was not found, so return 0 */
    return deleted;
}

