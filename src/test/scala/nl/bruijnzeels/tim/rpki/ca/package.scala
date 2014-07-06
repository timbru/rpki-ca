package nl.bruijnzeels.tim.rpki

import scala.language.implicitConversions

import java.net.URI

import net.ripe.ipresource.IpResourceSet

package object ca {
  implicit def stringToIpResourceSet(s: String): IpResourceSet = IpResourceSet.parse(s)
  implicit def stringToUri(s: String): URI = URI.create(s)
}