package nl.bruijnzeels.tim.rpki.ca.rc.signer

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Error
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassError

sealed trait SignerError extends ResourceClassError

case class RejectedCertificate(reason: String) extends SignerError
