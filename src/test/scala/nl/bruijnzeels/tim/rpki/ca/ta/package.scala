package nl.bruijnzeels.tim.rpki.ca

import net.ripe.ipresource.IpResourceSet
import scala.language.implicitConversions
import java.net.URI

package object ta {
  
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)
  
  implicit def stringToUri(s: String): URI = URI.create(s)

}