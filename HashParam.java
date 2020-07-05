import java.util.HashMap;

public class HashParam<K, V>
  extends HashMap
{
  public V putParam(K paramK, V paramV)
  {
    if (paramK == null) {
      paramK = null;
    }
    for (;;)
    {
      return paramK;
      if (paramV == null) {
        paramK = put(paramK, "");
      } else {
        paramK = put(paramK, paramV);
      }
    }
  }
}