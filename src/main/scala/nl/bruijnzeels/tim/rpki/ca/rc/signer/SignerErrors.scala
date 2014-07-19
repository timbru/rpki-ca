package nl.bruijnzeels.tim.rpki.ca.rc.signer

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Error

sealed trait SignerError extends Error

case class RejectedCertificate(reason: String) extends SignerError
