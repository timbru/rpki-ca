package nl.bruijnzeels.tim.rpki.ca

import net.ripe.ipresource.IpResourceSet
import scala.language.implicitConversions

package object ta {
  
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)

}