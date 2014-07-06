package nl.bruijnzeels.tim.rpki.ca.rc

import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.child.Child
import net.ripe.ipresource.IpResourceSet

/**
 * The name for this class: ResourceClass is taken from the "Provisioning Resource Certificates" Protocol.
 * See: http://tools.ietf.org/html/rfc6492
 *
 * Essentially a Certificate Authority as a logical entity may not get all their resources in a single bundle.
 * Instead resources may be grouped in what are called resource classes.
 *
 */
case class ResourceClass(resourceClassName: String, entitledResources: IpResourceSet, currentSigner: Signer = Signer(null), children: List[Child] = List.empty) {

  def applyEvent(event: ResourceClassEvent): ResourceClass = event match {
    case created: ResourceClassCreated => this
  }

}