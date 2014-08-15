package nl.bruijnzeels.tim.rpki.rrdp.app

import com.typesafe.config.{ ConfigFactory, Config }
import java.net.URI

object ApplicationOptions {

  private val config: Config = ConfigFactory.load()

  def rrdpPort: Int = config.getInt("rrdp.http.port")
  def rrdpHost: String = config.getString("rrdp.http.host")
  def rrdpBasePath: String = config.getString("rrdp.base.path")

  def rrdpBaseUri: URI = URI.create(s"http://${rrdpHost}:${rrdpPort}/${rrdpBasePath}")

}