package nl.bruijnzeels.tim.rpki.ca

import scala.language.implicitConversions

import java.net.URI

import net.ripe.ipresource.IpResourceSet

package object ta {
  
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)
  
  implicit def stringToUri(s: String): URI = URI.create(s)

}