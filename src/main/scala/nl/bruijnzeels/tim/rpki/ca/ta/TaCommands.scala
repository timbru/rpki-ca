package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.ipresource.IpResourceSet
import java.net.URI

sealed trait TaCommand extends Command

case class CreateTa(name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI) extends TaCommand
