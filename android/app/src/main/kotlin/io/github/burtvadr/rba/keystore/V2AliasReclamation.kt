package io.github.burtvadr.rba.keystore

/** Pure selection; only aliases in the exact V2-owned namespace qualify.
 * Caller must prove exclusive access and a complete canonical DB inventory. */
internal object V2AliasReclamation {
    private val id=Regex("[0-9a-f]{32}")
    private val role=Regex("rba-v2-([0-9a-f]{32})-(transport|biometric)")
    private val provisional=Regex("rba-v2-provisional-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    fun unrecorded(aliases:List<String>,recorded:Set<String>):List<String>{
        require(recorded.all{it.matches(id)&&it.any{c->c!='0'}})
        return aliases.distinct().filter{name->
            if(provisional.matches(name))true
            else role.matchEntire(name)?.groupValues?.get(1)?.let{it.any{c->c!='0'}&&it !in recorded}?:false
        }.sorted()
    }
}
