package water.fvec;

import java.util.ArrayList;

/**
 * Simple helper class which publishes some package private methods as public
 */
public class ChunkUtils {
    public static NewChunk[] createNewChunks(String name, byte[] vecTypes, int chunkId){
        return Frame.createNewChunks(name, vecTypes, chunkId);
    }

    public static void closeNewChunks(NewChunk[] nchks){
        Frame.closeNewChunks(nchks);
    }

    public static Chunk[] getChunks(Frame fr, int cidx) {
        Vec[] vecs = fr.vecs();
        ArrayList<Chunk> chunk_list = new ArrayList<>();
        for(Vec v : vecs){
            chunk_list.add(v.chunkForChunkIdx(cidx));
        }
       return chunk_list.toArray(new Chunk[chunk_list.size()]);
    }
}
