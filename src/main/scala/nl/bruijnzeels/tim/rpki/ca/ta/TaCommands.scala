package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.ipresource.IpResourceSet
import java.net.URI
import java.util.UUID

sealed trait TaCommand extends Command {
  def id: UUID
}

case class CreateTa(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI) extends TaCommand
