package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command

sealed trait TrustAnchorCommand extends Command {
  def id: UUID
}

case class TrustAnchorCreate(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI) extends TrustAnchorCommand