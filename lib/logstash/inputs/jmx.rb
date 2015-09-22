# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/json"

# This input plugin permits to retrieve metrics from remote Java applications using JMX.
# Every `polling_frequency`, it scans a folder containing json configuration 
# files describing JVMs to monitor with metrics to retrieve.
# Then a pool of threads will retrieve metrics and create events.
#
# ## The configuration:
#
# In Logstash configuration, you must set the polling frequency,
# the number of thread used to poll metrics and a directory absolute path containing
# json files with the configuration per jvm of metrics to retrieve.
# Logstash input configuration example:
# [source,ruby]
#     jmx {
#       //Required
#       path => "/apps/logstash_conf/jmxconf"
#       //Optional, default 60s
#       polling_frequency => 15
#       type => "jmx"
#       //Optional, default 4
#       nb_thread => 4
#     }
#
# Json JMX configuration example:
# [source,js]
#     {
#       //Required, JMX listening host/ip
#       "host" : "192.168.1.2",
#       //Required, JMX listening port
#       "port" : 1335,
#       //Optional, the username to connect to JMX
#       "username" : "user",
#       //Optional, the password to connect to JMX
#       "password": "pass",
#       //Optional, use this alias as a prefix in the metric name. If not set use <host>_<port>
#       "alias" : "test.homeserver.elasticsearch",
#       //Required, list of JMX metrics to retrieve
#       "queries" : [
#       {
#         //Required, the object name of Mbean to request
#         "object_name" : "java.lang:type=Memory",
#         //Optional, use this alias in the metrics value instead of the object_name
#         "object_alias" : "Memory"
#       }, {
#         "object_name" : "java.lang:type=Runtime",
#         //Optional, set of attributes to retrieve. If not set retrieve
#         //all metrics available on the configured object_name.
#         "attributes" : [ "Uptime", "StartTime" ],
#         "object_alias" : "Runtime"
#       }, {
#         //object_name can be configured with * to retrieve all matching Mbeans
#         "object_name" : "java.lang:type=GarbageCollector,name=*",
#         "attributes" : [ "CollectionCount", "CollectionTime" ],
#         //object_alias can be based on specific value from the object_name thanks to ${<varname>}.
#         //In this case ${type} will be replaced by GarbageCollector...
#         "object_alias" : "${type}.${name}"
#       }, {
#         "object_name" : "java.nio:type=BufferPool,name=*",
#         "object_alias" : "${type}.${name}"
#       } ]
#     }
#
# Here are examples of generated events. When returned metrics value type is 
# number/boolean it is stored in `metric_value_number` event field
# otherwise it is stored in `metric_value_string` event field.
# [source,ruby]
#     {
#       "@version" => "1",
#       "@timestamp" => "2014-02-18T20:57:27.688Z",
#       "host" => "192.168.1.2",
#       "path" => "/apps/logstash_conf/jmxconf",
#       "type" => "jmx",
#       "metric_path" => "test.homeserver.elasticsearch.GarbageCollector.ParNew.CollectionCount",
#       "metric_value_number" => 2212
#     }
#
# [source,ruby]
#     {
#       "@version" => "1",
#       "@timestamp" => "2014-02-18T20:58:06.376Z",
#       "host" => "localhost",
#       "path" => "/apps/logstash_conf/jmxconf",
#       "type" => "jmx",
#       "metric_path" => "test.homeserver.elasticsearch.BufferPool.mapped.ObjectName",
#       "metric_value_string" => "java.nio:type=BufferPool,name=mapped"
#     }
#
class LogStash::Inputs::Jmx < LogStash::Inputs::Base
  config_name 'jmx'

  #Class Var
  attr_accessor :regexp_group_alias_object
  attr_accessor :queue_conf

  # Path where json conf files are stored
  config :path, :validate => :string, :required => true

  # Indicate interval between two jmx metrics retrieval
  # (in s)
  config :polling_frequency, :validate => :number, :default => 60

  # Indicate number of thread launched to retrieve metrics
  config :nb_thread, :validate => :number, :default => 4

  #Error messages
  MISSING_CONFIG_PARAMETER = "Missing parameter '%s'."
  BAD_TYPE_CONFIG_PARAMETER = "Bad type for parameter '%{param}', expecting '%{expected}', found '%{actual}'."
  MISSING_QUERY_PARAMETER = "Missing parameter '%s' in queries[%d]."
  BAD_TYPE_QUERY = "Bad type for queries[%{index}], expecting '%{expected}', found '%{actual}'."
  BAD_TYPE_QUERY_PARAMETER = "Bad type for parameter '%{param}' in queries[%{index}], expecting '%{expected}', found '%{actual}'."
  # Verify that all required parameter are present in the conf_hash
  public
  def validate_configuration(conf_hash)
    validation_errors = []
    #Check required parameters in configuration
    ["host", "port","queries"].each do |param|
      validation_errors << MISSING_CONFIG_PARAMETER % param unless conf_hash.has_key?(param)
    end

    #Validate parameters type in configuration
    {"host" => String, "port" => Fixnum, "alias" => String }.each do |param, expected_type|
      if conf_hash.has_key?(param) && !conf_hash[param].instance_of?(expected_type)
        validation_errors << BAD_TYPE_CONFIG_PARAMETER % { :param => param, :expected => expected_type, :actual => conf_hash[param].class }
      end
    end

    if conf_hash.has_key?("queries")
      if !conf_hash["queries"].respond_to?(:each)
        validation_errors << BAD_TYPE_CONFIG_PARAMETER % { :param => 'queries', :expected => Enumerable, :actual => conf_hash['queries'].class }
      else
        conf_hash['queries'].each_with_index do |query,index|
          unless query.respond_to?(:[]) && query.respond_to?(:has_key?)
            validation_errors << BAD_TYPE_QUERY % {:index => index, :expected => Hash, :actual => query.class}
            next
          end
          #Check required parameters in each query
          ["object_name"].each do |param|
            validation_errors << MISSING_QUERY_PARAMETER % [param,index] unless query.has_key?(param)
          end
          #Validate parameters type in each query
          {"object_name" => String, "object_alias" => String }.each do |param, expected_type|
            if query.has_key?(param) && !query[param].instance_of?(expected_type)
              validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => param, :index => index, :expected => expected_type, :actual => query[param].class }
            end
          end

          if query.has_key?("attributes") && !query["attributes"].respond_to?(:each)
            validation_errors << BAD_TYPE_QUERY_PARAMETER % { :param => 'attributes', :index => index, :expected => Enumerable, :actual => query['attributes'].class }
          end
        end
      end
    end
    return validation_errors
  end

  private
  def replace_alias_object(r_alias_object,object_name)
    @logger.debug("Replace ${.*} variables from #{r_alias_object} using #{object_name}")
    group_alias = @regexp_group_alias_object.match(r_alias_object)
    if group_alias
      r_alias_object = r_alias_object.gsub('${'+group_alias[1]+'}',object_name.split(group_alias[1]+'=')[1].split(',')[0])
      r_alias_object = replace_alias_object(r_alias_object,object_name)
    end
    r_alias_object
  end

  private
  def send_event_to_queue(queue,host,metric_path,metric_value)
    @logger.debug('Send event to queue to be processed by filters/outputs')
    event = LogStash::Event.new
    event['host'] = host
    event['path'] = @path
    event['type'] = @type
    number_type = [Fixnum, Bignum, Float]
    boolean_type = [TrueClass, FalseClass]
    metric_path_substituted = metric_path.gsub(' ','_').gsub('"','')
    if number_type.include?(metric_value.class)
      @logger.debug("The value #{metric_value} is of type number: #{metric_value.class}")
      event['metric_path'] = metric_path_substituted
      event['metric_value_number'] = metric_value
    elsif boolean_type.include?(metric_value.class)
      @logger.debug("The value #{metric_value} is of type boolean: #{metric_value.class}")
      event['metric_path'] = metric_path_substituted+'_bool'
      event['metric_value_number'] = metric_value ? 1 : 0
    else
      @logger.debug("The value #{metric_value} is not of type number: #{metric_value.class}")
      event['metric_path'] = metric_path_substituted
      event['metric_value_string'] = metric_value.to_s
    end
    decorate(event)
    queue << event
  end

  # Thread function to retrieve metrics from JMX
  private
  def thread_jmx(queue_conf,queue)
    while true
      begin
        @logger.debug('Wait config to retrieve from queue conf')
        thread_hash_conf = queue_conf.pop
        @logger.debug("Retrieve config #{thread_hash_conf} from queue conf")

        @logger.debug('Check if jmx connection need a user/password')
        if thread_hash_conf.has_key?('username') and thread_hash_conf.has_key?('password')
          @logger.debug("Connect to #{thread_hash_conf['host']}:#{thread_hash_conf['port']} with user #{thread_hash_conf['username']}")
          jmx_connection = JMX::MBean.connection :host => thread_hash_conf['host'],
                                                 :port => thread_hash_conf['port'],
                                                 :url => thread_hash_conf['url'],
                                                 :username => thread_hash_conf['username'],
                                                 :password => thread_hash_conf['password']
        else
          @logger.debug("Connect to #{thread_hash_conf['host']}:#{thread_hash_conf['port']}")
          jmx_connection = JMX::MBean.connection :host => thread_hash_conf['host'],
                                                 :port => thread_hash_conf['port'],
                                                 :url => thread_hash_conf['url']
        end


        if thread_hash_conf.has_key?('alias')
          @logger.debug("Set base_metric_path to alias: #{thread_hash_conf['alias']}")
          base_metric_path = thread_hash_conf['alias']
        else
          @logger.debug("Set base_metric_path to host_port: #{thread_hash_conf['host']}_#{thread_hash_conf['port']}")
          base_metric_path = "#{thread_hash_conf['host']}_#{thread_hash_conf['port']}"
        end


        @logger.debug("Treat queries #{thread_hash_conf['queries']}")
        thread_hash_conf['queries'].each do |query|
          @logger.debug("Find all objects name #{query['object_name']}")
          jmx_object_name_s = JMX::MBean.find_all_by_name(query['object_name'], :connection => jmx_connection)

          if jmx_object_name_s.length > 0
            jmx_object_name_s.each do |jmx_object_name|
              if query.has_key?('object_alias')
                object_name = replace_alias_object(query['object_alias'],jmx_object_name.object_name.to_s)
                @logger.debug("Set object_name to object_alias: #{object_name}")
              else
                object_name = jmx_object_name.object_name.to_s
                @logger.debug("Set object_name to jmx object_name: #{object_name}")
              end

              if query.has_key?('attributes')
                @logger.debug("Retrieves attributes #{query['attributes']} to #{jmx_object_name.object_name}")
                query['attributes'].each do |attribute|
                  begin
                    jmx_attribute_value = jmx_object_name.send(attribute.snake_case)
                    if jmx_attribute_value.instance_of? Java::JavaxManagementOpenmbean::CompositeDataSupport
                      @logger.debug('The jmx value is a composite_data one')
                      jmx_attribute_value.each do |jmx_attribute_value_composite|
                        @logger.debug("Get jmx value #{jmx_attribute_value[jmx_attribute_value_composite]} for attribute #{attribute}.#{jmx_attribute_value_composite} to #{jmx_object_name.object_name}")
                        send_event_to_queue(queue, thread_hash_conf['host'], "#{base_metric_path}.#{object_name}.#{attribute}.#{jmx_attribute_value_composite}", jmx_attribute_value[jmx_attribute_value_composite])
                      end
                    else
                      @logger.debug("Get jmx value #{jmx_attribute_value} for attribute #{attribute} to #{jmx_object_name.object_name}")
                      send_event_to_queue(queue, thread_hash_conf['host'], "#{base_metric_path}.#{object_name}.#{attribute}", jmx_attribute_value)
                    end
                  rescue Exception => ex
                    @logger.warn("Failed retrieving metrics for attribute #{attribute} on object #{jmx_object_name.object_name}")
                    @logger.warn(ex.message)
                  end
                end
              else
                @logger.debug("No attribute to retrieve define on #{jmx_object_name.object_name}, will retrieve all")
                jmx_object_name.attributes.each_key do |attribute|
                  begin
                    jmx_attribute_value = jmx_object_name.send(attribute)
                    if jmx_attribute_value.instance_of? Java::JavaxManagementOpenmbean::CompositeDataSupport
                      @logger.debug('The jmx value is a composite_data one')
                      jmx_attribute_value.each do |jmx_attribute_value_composite|
                        @logger.debug("Get jmx value #{jmx_attribute_value[jmx_attribute_value_composite]} for attribute #{jmx_object_name.attributes[attribute]}.#{jmx_attribute_value_composite} to #{jmx_object_name.object_name}")
                        send_event_to_queue(queue, thread_hash_conf['host'], "#{base_metric_path}.#{object_name}.#{jmx_object_name.attributes[attribute]}.#{jmx_attribute_value_composite}", jmx_attribute_value[jmx_attribute_value_composite])
                      end
                    else
                      @logger.debug("Get jmx value #{jmx_attribute_value} for attribute #{jmx_object_name.attributes[attribute]} to #{jmx_object_name.object_name}")
                      send_event_to_queue(queue, thread_hash_conf['host'], "#{base_metric_path}.#{object_name}.#{jmx_object_name.attributes[attribute]}", jmx_attribute_value)
                    end
                  rescue Exception => ex
                    @logger.warn("Failed retrieving metrics for attribute #{attribute} on object #{jmx_object_name.object_name}")
                    @logger.warn(ex.message)
                  end
                end
              end
            end
          else
            @logger.warn("No jmx object found for #{query['object_name']}")
          end
        end
        jmx_connection.close
      rescue LogStash::ShutdownSignal
        break #free
      rescue Exception => ex
        @logger.error(ex.message)
        @logger.error(ex.backtrace.join("\n"))
      end
    end
  end

  public
  def register
    require 'thread'
    require 'jmx4r'

    @logger.info("Create queue dispatching JMX requests to threads")
    @queue_conf = Queue.new

    @logger.info("Compile regexp for group alias object replacement")
    @regexp_group_alias_object = Regexp.new('(?:\${(.*?)})+')
  end

  public
  def run(queue)
    begin
      threads = []
      @logger.info("Initialize #{@nb_thread} threads for JMX metrics collection")
      @nb_thread.times do
        threads << Thread.new { thread_jmx(@queue_conf,queue) }
      end

      while !@interrupted
        @logger.info("Loading configuration files in path", :path => @path)
        Dir.foreach(@path) do |item|
          next if item == '.' or item == '..'
          begin
            file_conf = File.join(@path, item)
            @logger.debug? && @logger.debug("Loading configuration from file", :file => file_conf)
            config_string = File.read(file_conf)
            conf_hash = LogStash::Json.load(config_string)
            validation_errors = validate_configuration(conf_hash)
            if validation_errors.empty?
              @logger.debug? && @logger.debug("Add configuration to the queue", :config => conf_hash)
              @queue_conf << conf_hash
            else
              @logger.warn("Issue with configuration file", :file => file_conf,
              :validation_errors => validation_errors)
            end
          rescue Exception => ex
            @logger.warn("Issue loading configuration from file", :file => file_conf,
              :exception => ex.message, :backtrace => ex.backtrace)
          end
        end
        @logger.debug('Wait until the queue conf is empty')
        delta=0
        until @queue_conf.empty?
          @logger.debug("There are still #{@queue_conf.size} messages in the queue conf. Sleep 1s.")
          delta=delta+1
          sleep(1)
        end
        wait_time=@polling_frequency-delta
        if wait_time>0
          @logger.debug("Wait #{wait_time}s (#{@polling_frequency}-#{delta}(seconds wait until queue conf empty)) before to launch again a new jmx metrics collection")
          sleep(wait_time)
        else
          @logger.warn("The time taken to retrieve metrics is more important than the retrieve_interval time set.
                       \nYou must adapt nb_thread, retrieve_interval to the number of jvm/metrics you want to retrieve.")
        end
      end
    rescue LogStash::ShutdownSignal
        #exiting
    rescue Exception => ex
      @logger.error(ex.message)
      @logger.error(ex.backtrace.join("\n"))
    ensure
      threads.each do |thread|
        thread.raise(LogStash::ShutdownSignal) if thread.alive?
      end
    end

  end

  public
  def close
    @interrupted = true
  end # def close
end
